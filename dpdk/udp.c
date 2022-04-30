#include <netinet/ip.h>
#include <rte_eal.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <unistd.h>


#define NUM_MBUF_SIZE (4096-1)
#define BURST_SIZE 32

#define MAKE_IPVE_ADDR(a , b , c , d) (a + (b <<8) + (c << 16) + (d <<24))

#define IPV4_VHL_DEF ( (IPVERSION << 4)  | RTE_IPV4_MIN_IHL)

static uint32_t gLocalIp = MAKE_IPVE_ADDR(192,168,112 , 131);

int gDpdkPort = 0;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

static const struct rte_eth_conf port_conf_default = {

	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};


static void ng_init_port(struct rte_mempool *mbuf_pool) {
	
	int count = rte_eth_dev_count_avail();

	if (count <= 0) {
		rte_exit(EXIT_FAILURE , "eth dev count avali");
	}

	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(gDpdkPort , &dev_info);

	const int num_rx_queue = 1;
	const int num_tx_queue = 1;

	struct rte_eth_conf port_conf = port_conf_default;

	rte_eth_dev_configure(gDpdkPort , num_rx_queue , num_tx_queue, &port_conf);


	int setup_rx = rte_eth_rx_queue_setup(gDpdkPort , 0 , 1024 , 
			rte_eth_dev_socket_id(gDpdkPort) , 
			NULL , 
			mbuf_pool);

	if (setup_rx < 0) {
		rte_exit(EXIT_FAILURE , "rx queue setup");
	}

	
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;

	int setup_tx = rte_eth_tx_queue_setup(gDpdkPort , 0 , 1024 , rte_eth_dev_socket_id(gDpdkPort) , &txq_conf);

	if (setup_tx < 0 ){
		rte_exit(EXIT_FAILURE , "tx queue setup");
	}


	int start = rte_eth_dev_start(gDpdkPort);

	if (start < 0) {
		rte_exit(EXIT_FAILURE , "eth dev start");
	}

	printf("eth dev started\n");

}

// dst_mac:  is 48bit. there is uint8_t[6] . so arg type is uint8_t*
static int ng_encode_arp_pkt(uint8_t *msg, uint8_t *dst_mac , uint32_t sip , uint32_t dip){

	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	
	rte_memcpy(eth->s_addr.addr_bytes , gSrcMac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes , dst_mac , RTE_ETHER_ADDR_LEN);

	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	struct rte_arp_hdr *arphdr = (struct rte_arp_hdr *)(eth + 1);
	arphdr->arp_hardware = htons(1);
	arphdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4); // ?
	arphdr->arp_hlen = RTE_ETHER_ADDR_LEN;
	arphdr->arp_plen= sizeof(uint32_t);// ?
	arphdr->arp_opcode = htons(2);


	rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes , gSrcMac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes , dst_mac , RTE_ETHER_ADDR_LEN);

	arphdr->arp_data.arp_sip = sip;
	arphdr->arp_data.arp_tip = dip;

	return 0;

}

static struct rte_mbuf * ng_send_arp(struct rte_mempool *mbuf_pool , uint8_t *dst_mac , uint32_t sip , uint32_t dip){

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

	if (mbuf == NULL)	{
			rte_exit(EXIT_FAILURE , "pkt mbuf alloc");
	}

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf , uint8_t *);

	ng_encode_arp_pkt(pkt_data , dst_mac , sip , dip);
	
	return mbuf;

}


// rfc document support 
static uint16_t dpdk_icmp_checksum(uint16_t *addr , int count) {

	register long sum = 0;

	while(count > 1 ) {
		
		sum += *(unsigned short *)addr++;
		count -= 2;
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while(sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}


	return ~sum;
}

static int ng_encode_imcp_pkt(uint8_t *msg , uint8_t *src_mac , uint8_t *dst_mac , uint32_t sip , uint32_t tip , uint16_t ident , uint16_t seq_nb){

	struct rte_ether_hdr *etherhdr = (struct rte_ether_hdr *) msg;

	// etherhdr->s_addr.addr_bytes
	// ether pkt	
	rte_memcpy(etherhdr->s_addr.addr_bytes , src_mac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(etherhdr->d_addr.addr_bytes , dst_mac , RTE_ETHER_ADDR_LEN);
	
	etherhdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// ip pkt
	struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(etherhdr +1);
	iphdr->version_ihl = 0x45;	
	iphdr->type_of_service = 0;	
	iphdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) );	
	iphdr->packet_id = 0 ;
	iphdr->fragment_offset = 0;
	iphdr->time_to_live = 64; // ttl
	iphdr->next_proto_id = IPPROTO_ICMP;
	iphdr->src_addr = sip;
	iphdr->dst_addr = tip;

	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

	
	// icmp 
	
	struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
	
	icmphdr->icmp_type =RTE_IP_ICMP_ECHO_REPLY;
	icmphdr->icmp_code = 0;
	icmphdr->icmp_ident = ident;
	icmphdr->icmp_seq_nb = seq_nb;
	icmphdr->icmp_cksum = dpdk_icmp_checksum((uint16_t *)icmphdr , sizeof(struct rte_icmp_hdr));

	return 0;
}


static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool , uint8_t *dst_mac , uint32_t sip , uint32_t tip , uint16_t ident , uint16_t seq_nb) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

	if (mbuf == NULL) {
		rte_exit(EXIT_FAILURE , "icmp alloc");
	}


	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;


	uint8_t *msg = rte_pktmbuf_mtod(mbuf , uint8_t *);
	ng_encode_imcp_pkt(msg ,gSrcMac , dst_mac , sip , tip , ident , seq_nb);


	return mbuf;
}


static int ng_encode_udp_pkt(uint8_t *msg, uint8_t *dst_mac , uint32_t sip , uint32_t tip, uint16_t src_port , uint16_t dst_port , unsigned char *data , uint16_t total_length) {

	
	struct rte_ether_hdr *ehdr = (struct rte_ether_hdr *)msg;

	rte_memcpy(ehdr->s_addr.addr_bytes , gSrcMac , RTE_ETHER_ADDR_LEN);
	rte_memcpy(ehdr->d_addr.addr_bytes , dst_mac , RTE_ETHER_ADDR_LEN);
	
	ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ehdr+1);

	iphdr->total_length = htons( total_length - sizeof(struct rte_ether_hdr) );
	iphdr->version_ihl = IPV4_VHL_DEF;
	iphdr->type_of_service = 0;


	iphdr->packet_id = 0;
	iphdr->fragment_offset = 0;
	iphdr->time_to_live = 64;
	iphdr->next_proto_id = IPPROTO_UDP;

	iphdr->dst_addr = tip;
	iphdr->src_addr = sip;
	
	iphdr->hdr_checksum = 0;
	iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

	// udp
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	udphdr->src_port = src_port;
	udphdr->dst_port = dst_port;
	
	uint16_t udp_len = total_length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);

	udphdr->dgram_len = htons(udp_len);

	uint16_t data_len = udp_len - sizeof(struct rte_udp_hdr);

	rte_memcpy((uint8_t *)(udphdr + 1) , data, data_len);
	
	udphdr->dgram_cksum = 0;
	udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);

	struct in_addr addr;
	addr.s_addr = sip;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(src_port));

	addr.s_addr = tip;
	printf("dst: %s:%d , ", inet_ntoa(addr), ntohs(dst_port));

	printf("udp send msg is %s , len is %d \n" , data , data_len);

	return 0;

}


static struct rte_mbuf *ng_send_udp(struct rte_mempool *mbuf_pool , uint8_t *dst_mac , struct rte_ipv4_hdr *ip , struct rte_udp_hdr *udp , unsigned char *data  , uint16_t data_len) {

	
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

	if (mbuf == NULL) {
		rte_exit(EXIT_FAILURE , "udp pkt alloc");
	}

	const unsigned total_length = data_len + 42;

	mbuf->pkt_len =  total_length ;
	mbuf->data_len = total_length ;

	uint8_t * msg = rte_pktmbuf_mtod(mbuf , uint8_t *);

	uint32_t sip = 0;
	uint32_t tip = 0;

	rte_memcpy(&sip , &ip->dst_addr , sizeof(uint32_t));
	rte_memcpy(&tip , &ip->src_addr , sizeof(uint32_t));

	uint16_t s_port = 0;
	uint16_t t_port = 0;

	rte_memcpy(&s_port , &udp->dst_port , sizeof(uint16_t));
	rte_memcpy(&t_port , &udp->src_port , sizeof(uint16_t));
	
	printf("data len %d \n" , data_len);
	
	ng_encode_udp_pkt(msg , dst_mac , sip , tip  , s_port , t_port , data , total_length);


	return mbuf ;

}


int main(int argc , char *argv[]) {


	int eal = rte_eal_init(argc , argv);

	if (eal < 0){
		rte_exit(EXIT_FAILURE , "eal init");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf" , 
			NUM_MBUF_SIZE , 0 , 0 , 
			RTE_MBUF_DEFAULT_BUF_SIZE , rte_socket_id());

	if (mbuf_pool == NULL){
		rte_exit(EXIT_FAILURE , "mbuf pool");
	}
	
	ng_init_port(mbuf_pool);

	rte_eth_macaddr_get(gDpdkPort , (struct rte_ether_addr*)gSrcMac);


	while(1) {

		struct rte_mbuf*mbufs[BURST_SIZE];

		uint16_t recv_num = rte_eth_rx_burst(gDpdkPort , 0 , mbufs , BURST_SIZE);

		if (recv_num > BURST_SIZE) {
			rte_exit(EXIT_FAILURE , "rx burst");
		}


		unsigned i = 0;
		for (i = 0 ; i < recv_num ; i++){
		
				struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i] , 
					struct rte_ether_hdr *);

				if(ehdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_ARP)){
					
					struct rte_arp_hdr *arphdr = rte_pktmbuf_mtod_offset(mbufs[i] , struct rte_arp_hdr* , sizeof(struct rte_ether_hdr));


					if ( arphdr->arp_data.arp_tip == gLocalIp){



						struct in_addr addr;
						addr.s_addr = arphdr->arp_data.arp_sip;

						printf("arp ---> src:%s \t" , inet_ntoa(addr));
						addr.s_addr = gLocalIp;
						printf("local ---> :%s \n" , inet_ntoa(addr));


						struct rte_mbuf *arp_buf = ng_send_arp(mbuf_pool , arphdr->arp_data.arp_sha.addr_bytes , arphdr->arp_data.arp_tip , arphdr->arp_data.arp_sip);
	
						rte_eth_tx_burst(gDpdkPort , 0 , &arp_buf , 1);
					
						rte_pktmbuf_free(arp_buf);
					

					}
				}

				if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

					struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

					
					struct in_addr in;
					in.s_addr = iphdr->src_addr;

				
					
					// icmp
					if (iphdr->next_proto_id == IPPROTO_ICMP) {

						printf("icmp ---> src is ip is %s \n" , inet_ntoa(in));
						
						struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr+1);

						// RTE_IP_ICMP_ECHO_REQUEST	
						
						if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
								
							struct rte_mbuf *mbuf = ng_send_icmp(mbuf_pool , ehdr->s_addr.addr_bytes , iphdr->dst_addr , iphdr->src_addr , icmphdr->icmp_ident , icmphdr->icmp_seq_nb);

							rte_eth_tx_burst(gDpdkPort , 0 , &mbuf , 1);
							
							rte_pktmbuf_free(mbuf);
							
						}

					}


			
					// udp
					
					if (iphdr->next_proto_id == IPPROTO_UDP) {

						struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(iphdr +1);
						
						struct in_addr in;
						in.s_addr = iphdr->src_addr;

						printf("udp src is %s \t" , inet_ntoa(in));
						in.s_addr = iphdr->dst_addr;
						printf("dst is %s \n" , inet_ntoa(in));

						// (udp header length) + (data len)						
						uint16_t udp_len = ntohs(udp->dgram_len);
						*((char *)udp + udp_len) = '\0';
						printf("udp msg is %s , len is %d\n" , (char *)(udp + 1) , udp_len);
						
						// recv 
						uint8_t dst_mac[RTE_ETHER_ADDR_LEN];
						rte_memcpy(dst_mac , ehdr->s_addr.addr_bytes , RTE_ETHER_ADDR_LEN);

						struct rte_mbuf * udp_pkt = ng_send_udp(mbuf_pool , dst_mac , iphdr , udp , (unsigned char *)(udp+1) , udp_len -sizeof(struct rte_udp_hdr));
						rte_eth_tx_burst(gDpdkPort , 0 , &udp_pkt , 1);
						
						rte_pktmbuf_free(udp_pkt);

					}

					
				}


				rte_pktmbuf_free(mbufs[i]);
	
			}


	}


}
