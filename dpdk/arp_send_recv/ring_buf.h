#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_malloc.h>

#include <stdio.h>
#include <memory.h>


#define RING_SIZE 1024


struct ring_buf {
	
	struct rte_ring *in;
	struct rte_ring *out;

};

static struct ring_buf *rInst = NULL;


static struct ring_buf *
ring_instance() {
	
	if (rInst == NULL) {
		
		rInst = (struct ring_buf *)rte_malloc("ring_buf" , sizeof(struct ring_buf),0);
		memset(rInst , 0 , sizeof(struct ring_buf));

		rInst->in = rte_ring_create("in ring_buf" , RING_SIZE , rte_socket_id() , RING_F_SC_DEQ | RING_F_SP_ENQ);
		rInst->out = rte_ring_create("out ring_buf" , RING_SIZE , rte_socket_id() , RING_F_SC_DEQ | RING_F_SP_ENQ);

	}

	return rInst;

}

