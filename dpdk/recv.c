#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <arpa/inet.h>



#define NUM_MBUF_SIZE  (4096-1)

#define BURST_SIZE 32

int gDpdkPort = 0;

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};


static void 
ng_init_port(struct rte_mempool *mbuf_pool){

	uint16_t dev_avali_count = rte_eth_dev_count_avail();

	if (dev_avali_count <= 0 ){
		rte_exit(EXIT_FAILURE , "eth not found");	
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPort , &dev_info);
	
	const int num_rx_queues = 1;
	const int num_tx_queues = 0;
	struct rte_eth_conf port_conf = port_conf_default;

	rte_eth_dev_configure(gDpdkPort , num_rx_queues , num_tx_queues , &port_conf);


	int set_up_res = rte_eth_rx_queue_setup(gDpdkPort , 0 , 128 , rte_eth_dev_socket_id(gDpdkPort), NULL , mbuf_pool);

	if (set_up_res < 0){
		rte_exit(EXIT_FAILURE , "set up rx queue");
	}

	int start_res = rte_eth_dev_start(gDpdkPort);

	if (start_res < 0){
		rte_exit(EXIT_FAILURE , "eth dev start");
	}
	
	printf("eth dev started \n");
}

int
main(int argc , char *argv[]){
	
	if (rte_eal_init(argc , argv) < 0 ) {
		rte_exit(EXIT_FAILURE , "eal init");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool" , NUM_MBUF_SIZE , 0 , 0, RTE_MBUF_DEFAULT_BUF_SIZE , rte_socket_id());
	
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE , "mbuf_pool init");
	}

	ng_init_port(mbuf_pool);

	while(1){

		struct rte_mbuf *mbufs[BURST_SIZE];

		uint16_t recv_num = rte_eth_rx_burst(gDpdkPort , 0 , mbufs , BURST_SIZE);


		if (recv_num > BURST_SIZE) {
			rte_exit(EXIT_FAILURE , "rx burst");
		}


		unsigned i = 0;

		for (i = 0; i < recv_num ; i++){

			
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr * );
			
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			
			struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i] , struct rte_ipv4_hdr * ,  sizeof(struct rte_ether_hdr));

			if(iphdr->next_proto_id == IPPROTO_UDP) {
					
				struct rte_udp_hdr *udphdr = rte_pktmbuf_mtod_offset(mbufs[i] ,
						struct rte_udp_hdr * , 
						sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

				uint16_t length = ntohs( udphdr->dgram_len);

				*((char *)udphdr + length) = '\0';

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf(" src ip is %s , port  %d \n" , inet_ntoa(addr) , udphdr->src_port);

				addr.s_addr = iphdr->dst_addr;
				printf(" dst ip is %s , port is %d \n" , inet_ntoa(addr) , udphdr->dst_port);

				rte_pktmbuf_free(mbufs[i]);

			}


		}



	}

}
