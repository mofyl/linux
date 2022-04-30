#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <unistd.h>


#define NUM_MBUF_SIZE (4096-1)
#define BURST_SIZE 32


#define MAKE_IPVE_ADDR(a , b , c , d) (a + (b <<8) + (c << 16) + (d <<24))

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

	eth->ether_type =htons( RTE_ETHER_TYPE_ARP);

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


					struct in_addr addr;
					addr.s_addr = arphdr->arp_data.arp_sip;

					if ( arphdr->arp_data.arp_tip == gLocalIp){

						printf("arp ---> src:%s " , inet_ntoa(addr));
						addr.s_addr = gLocalIp;
						printf("local ---> :%s \n" , inet_ntoa(addr));




						struct rte_mbuf *arp_buf = ng_send_arp(mbuf_pool , arphdr->arp_data.arp_sha.addr_bytes , arphdr->arp_data.arp_tip , arphdr->arp_data.arp_sip);

						rte_eth_tx_burst(gDpdkPort , 0 , &arp_buf , 1);
					
						rte_pktmbuf_free(arp_buf);
					

					}
				}

				rte_pktmbuf_free(mbufs[i]);
	
			}


	}


}
