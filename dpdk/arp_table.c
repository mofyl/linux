#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "arp_table_list.h"

#define NUM_MBUF (4096-1)
#define MBUF_SIZE 32

#define MAKE_IP(a , b ,c ,d) (a + (b << 8) + (c << 16) + (d << 24))



int gDpdkEth = 0;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

static uint32_t gSrcIp = MAKE_IP(192 , 168 , 112 , 131);

static uint8_t gIPVhlDef = (IPVERSION << 4 ) | RTE_IPV4_MIN_IHL;



static const struct rte_eth_conf eth_conf_default = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};



struct hdr_arg {
	
	uint32_t total_len;
	uint8_t dst_mac[RTE_ETHER_ADDR_LEN];
	uint32_t sip;
	uint32_t tip;

	uint16_t data_type;

	void *data;
};

struct icmp_data {
	
	uint16_t ident;
	uint16_t seq;
};

struct udp_data{
	char * data;
	uint32_t data_len;
	uint16_t s_port;
	uint16_t t_port;
};




static void ng_init_dev(struct rte_mempool *mbuf_pool) {
	
	if (rte_eth_dev_count_avail() <= 0) {
		rte_exit(EXIT_FAILURE , "dev count avail");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkEth , &dev_info);

	const int num_rx_queues = 1;
	const int num_tx_queues = 1;
	
	struct rte_eth_conf eth_conf = eth_conf_default;

	rte_eth_dev_configure(gDpdkEth, num_rx_queues , num_tx_queues , &eth_conf);
	
	int rx_que_setup_res = rte_eth_rx_queue_setup(gDpdkEth , 0 , 1024 , rte_eth_dev_socket_id(gDpdkEth) ,
			NULL , mbuf_pool);

	if (rx_que_setup_res < 0) {
		rte_exit(EXIT_FAILURE , "rx queue set up res");
	}

	struct rte_eth_txconf tx_conf = dev_info.default_txconf;
	// tx_conf.offloads = eth_conf.rxmode.offloads;

	int tx_setup_res = rte_eth_tx_queue_setup(gDpdkEth , 0 , 1024 , 
			rte_eth_dev_socket_id(gDpdkEth) , 
			&tx_conf);
	
	if(tx_setup_res < 0) {
		rte_exit(EXIT_FAILURE , "tx queue setup");
	}



	if (rte_eth_dev_start(gDpdkEth) < 0 ){
		rte_exit(EXIT_FAILURE , "rx eth dev start");
	}

	printf("rte eth dev started \n");
}

static int encode_arp_pkt(uint8_t *msg , uint8_t *dst_mac, 
		uint32_t sip, uint32_t tip) {
	
	struct rte_ether_hdr *ehdr = (struct rte_ether_hdr *)msg;

	ehdr->ether_type = htons( RTE_ETHER_TYPE_ARP);
	rte_memcpy(ehdr->s_addr.addr_bytes , gSrcMac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(ehdr->d_addr.addr_bytes , dst_mac , RTE_ETHER_ADDR_LEN);

	struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ehdr + 1);
	arphdr->arp_hardware = htons(1);
	arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arphdr->arp_hlen = RTE_ETHER_ADDR_LEN;
	arphdr->arp_plen = sizeof(uint32_t);
	arphdr->arp_opcode = htons(2);

	rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes , gSrcMac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes , dst_mac , RTE_ETHER_ADDR_LEN);

	arphdr->arp_data.arp_sip = sip;
	arphdr->arp_data.arp_tip = tip;


	return 0;
}

static struct rte_mbuf *ng_encode_arp_pkt(struct rte_mempool *mbuf_pool , 
		uint8_t *dst_mac , uint32_t sip , uint32_t tip) {
	
	int total_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

	if (mbuf == NULL) {
		rte_exit(EXIT_FAILURE , "arp mbuf alloc");
	}

	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *msg = rte_pktmbuf_mtod(mbuf , uint8_t *);
	
	encode_arp_pkt(msg , dst_mac , sip , tip);

	return mbuf;
}


static uint16_t icmp_cksum(uint16_t *addr , int count) {

	register long sum = 0;

	while(count > 1 ){

		sum += *(uint16_t *)addr++;
		count -= 2;
	}

	if (count > 0) {
		sum += *(uint8_t *)addr;
	}

	while(sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
		
	}


	return ~sum;
}


static int encode_icmp_pkt(uint8_t *msg , struct hdr_arg args) {
	
	struct rte_ether_hdr *ehdr = (struct rte_ether_hdr *)msg;

	ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	rte_memcpy(ehdr->s_addr.addr_bytes , gSrcMac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(ehdr->d_addr.addr_bytes , args.dst_mac , RTE_ETHER_ADDR_LEN);


	struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ehdr + 1);

	iphdr->packet_id = 0;
	iphdr->fragment_offset = 0;
	iphdr->next_proto_id = IPPROTO_ICMP;

	iphdr->src_addr = args.sip;
	iphdr->dst_addr = args.tip;

	iphdr->time_to_live = 64;
	iphdr->total_length = htons( args.total_len- sizeof(struct rte_ether_hdr) );
	iphdr->type_of_service  = 0;
	iphdr->version_ihl = gIPVhlDef;

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
	
	struct icmp_data *icmp_arg = (struct icmp_data *)args.data;
	
	struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

	icmphdr->icmp_code = 0;
	icmphdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmphdr->icmp_ident = icmp_arg->ident;
	icmphdr->icmp_seq_nb = icmp_arg->seq;

	icmphdr->icmp_cksum = 0;
	icmphdr->icmp_cksum = icmp_cksum((uint16_t *)icmphdr , sizeof(struct rte_icmp_hdr));
	
	return 0;

}

static struct rte_mbuf *ng_encode_icmp_pkt(struct rte_mempool *mbuf_pool , struct hdr_arg args) {


	uint32_t total_len = sizeof(struct rte_ether_hdr) + 
		sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

	if (mbuf == NULL){
		rte_exit(EXIT_FAILURE, "icmp mbuf alloc");
	}

	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	args.total_len = total_len;

	uint8_t * msg = rte_pktmbuf_mtod(mbuf , uint8_t *);
	encode_icmp_pkt(msg , args);


	return mbuf;

}


static int 
encode_udp_pkt(uint8_t *msg , struct hdr_arg args) {
	
	struct rte_ether_hdr * ehdr = (struct rte_ether_hdr *)msg;

	ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	rte_memcpy(ehdr->s_addr.addr_bytes , gSrcMac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(ehdr->d_addr.addr_bytes , args.dst_mac , RTE_ETHER_ADDR_LEN);

	struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ehdr + 1);

	iphdr->packet_id = 0;
	iphdr->fragment_offset = 0;
	
	iphdr->type_of_service = 0;
	iphdr->version_ihl = gIPVhlDef;
	iphdr->next_proto_id = IPPROTO_UDP;

	iphdr->src_addr = args.sip;
	iphdr->dst_addr = args.tip;

	iphdr->time_to_live = 64;
	iphdr->total_length = htons( args.total_len - sizeof(struct rte_ether_hdr) );

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);
	
	struct udp_data *data = (struct udp_data *)args.data;

	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	udphdr->src_port = data->s_port;
	udphdr->dst_port = data->t_port;
	udphdr->dgram_len = htons( args.total_len - sizeof(struct rte_ether_hdr) -sizeof(struct rte_ipv4_hdr) );

	rte_memcpy((uint8_t *)(udphdr + 1) , data->data , data->data_len);

	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr , udphdr);

	struct in_addr in;
	in.s_addr = args.sip;
	printf("udp send: sip is %s , " , inet_ntoa(in));
	in.s_addr = args.tip;
	printf("tip is %s \t s_port is %d , t_port is %d , msg is %s , len is %d \n" , 
			inet_ntoa(in) ,
			htons( data->s_port) ,
			htons( data->t_port ), 
			data->data , 
			data->data_len);

	return 0;
}

static struct rte_mbuf *
ng_encode_udp_pkt(struct rte_mempool *mbuf_pool , struct hdr_arg args) {


	if (args.data == NULL){
		rte_exit(EXIT_FAILURE , "udp arg data is null");
	}

	struct udp_data *udp_arg = (struct udp_data *) (args.data);

	uint32_t total_len = sizeof(struct rte_ether_hdr) + 
		sizeof(struct rte_ipv4_hdr) + 
		sizeof(struct rte_udp_hdr) + 
		udp_arg->data_len;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

	if (mbuf == NULL) {
		rte_exit(EXIT_FAILURE , "udp mem pool alloc");
	}

	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *msg = rte_pktmbuf_mtod(mbuf , uint8_t *);

	args.total_len = total_len;

	encode_udp_pkt(msg , args);

	return mbuf;

}


int main(int argc , char *argv[]) {

	
	if (rte_eal_init(argc , argv) < 0) {
		rte_exit(EXIT_FAILURE , "eal init");
	}

	
 struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("pkt mbuf" , NUM_MBUF ,
			0 , 0, RTE_MBUF_DEFAULT_BUF_SIZE , 
			rte_socket_id());

 if (mbuf_pool == NULL)  {
	 rte_exit(EXIT_FAILURE , "rte mbuf");
 }

	
 ng_init_dev(mbuf_pool);

 rte_eth_macaddr_get(gDpdkEth , (struct rte_ether_addr *)gSrcMac);

 while(1){

	struct rte_mbuf *mbufs[MBUF_SIZE];

	uint16_t recv_num = rte_eth_rx_burst(gDpdkEth , 0 , mbufs , MBUF_SIZE);

	if (recv_num > MBUF_SIZE) {
		rte_exit(EXIT_FAILURE , "rx burst");
	}

	unsigned i=0;

	for (i = 0 ; i < recv_num; i++) {

		struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i] , struct rte_ether_hdr *);


		struct hdr_arg args;

		rte_memcpy(args.dst_mac , ehdr->s_addr.addr_bytes , RTE_ETHER_ADDR_LEN);



		if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
			
			struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(ehdr +1);
			// struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbufs[i] , struct rte_arp_hdr * , sizeof(struct rte_ether_hdr));
			
			if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) ) {

				if (arphdr->arp_data.arp_tip == gSrcIp){
				
					struct in_addr in;
					in.s_addr = arphdr->arp_data.arp_sip;
					printf("arp : src ip is %s \t" , inet_ntoa(in));
					in.s_addr = arphdr->arp_data.arp_tip;
					printf("target ip is %s \n" , inet_ntoa(in));

					struct rte_mbuf *arp_pkt = ng_encode_arp_pkt(mbuf_pool , 
						arphdr->arp_data.arp_sha.addr_bytes , 
						arphdr->arp_data.arp_tip , 
						arphdr->arp_data.arp_sip);

					rte_eth_tx_burst(gDpdkEth , 0 , &arp_pkt , 1);

					rte_pktmbuf_free(arp_pkt);

				}
			}


			if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
				
				uint8_t *hw_addr = ng_get_dst_macaddr(arphdr->arp_data.arp_sip);

				if (hw_addr == NULL) {

					struct arp_table* table = arp_table_instance();

					struct arp_entry *entry = rte_malloc("arp entry" , sizeof(struct arp_entry) , 0);

					if (entry != NULL) {

						memset(entry, 0 , sizeof(struct arp_entry));
						entry->ip = arphdr->arp_data.arp_sip;
						rte_memcpy(entry->hwaddr , arphdr->arp_data.arp_sha.addr_bytes , RTE_ETHER_ADDR_LEN);
						entry->type = ARP_ENTRY_TYPE_DYNAMIC;
						
						LL_ADD( entry , table->entries );
						table->count++;
					}
					
				}




			}

		}


		if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

			
			struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ehdr + 1);

			args.sip = iphdr->dst_addr;
			args.tip = iphdr->src_addr;


			if (iphdr->next_proto_id == IPPROTO_ICMP) {
				
					struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
					
					struct in_addr in;
					in.s_addr = iphdr->src_addr;
					printf("icmp : src ip is %s \t" , inet_ntoa(in));
					in.s_addr = iphdr->dst_addr;
					printf("target ip is %s \n" , inet_ntoa(in));

					struct icmp_data icmp_arg = {
						.ident = icmphdr->icmp_ident,
						.seq = icmphdr->icmp_seq_nb,
					};
					
					args.data = &icmp_arg;

					struct rte_mbuf *icmp_pkt = ng_encode_icmp_pkt(mbuf_pool , args);

					rte_eth_tx_burst(gDpdkEth , 0 , &icmp_pkt , 1);

					rte_pktmbuf_free(icmp_pkt);
			}


			if (iphdr->next_proto_id == IPPROTO_UDP) {
				
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

				struct in_addr in;
				in.s_addr = iphdr->src_addr;
				printf("udp : src ip is %s," , inet_ntoa(in));
				in.s_addr = iphdr->dst_addr;
				printf("target ip is %s \t" , inet_ntoa(in));
				printf("src port is %d , dst port is %d \t" , ntohs( udphdr->src_port) ,ntohs( udphdr->dst_port) );
				
				uint16_t udp_total_len = ntohs(udphdr->dgram_len);
				uint16_t udp_data_len = udp_total_len - sizeof(struct rte_udp_hdr);
				
				*( (char *)udphdr + udp_total_len ) = '\0';
				
				printf("recv msg is %s  , len is %d\n" , (char *)(udphdr + 1) , udp_data_len);

				char recv_buf[udp_data_len];
				rte_memcpy(recv_buf , (char *)(udphdr+1) , udp_data_len);
				
				struct udp_data data = {
					.s_port = udphdr->dst_port,
					.t_port = udphdr->src_port,
					.data = recv_buf,
					.data_len = udp_data_len,
				};
				
				args.data = &data;

				struct rte_mbuf *udp_pkt = ng_encode_udp_pkt(mbuf_pool , args);

				rte_eth_tx_burst(gDpdkEth , 0 , &udp_pkt , 1);

				rte_pktmbuf_free(udp_pkt);

			}


		}

	
	rte_pktmbuf_free(mbufs[i]);

	}


 }

}
