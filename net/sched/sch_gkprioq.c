 /*
 * net/sched/sch_gkprioq.c  Gatekeeper Priority Queue.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Nishanth Devarajan, <ndev_2021@gmail.com>
 *	        original idea by Michel Machado, Cody Doucette and Meng Xiang
 *
 */

#include <linux/string.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <asm/byteorder.h>

/* Priority markers */
#define MAX_PRIORITY 63
#define HALF_MAX_PRIORITY 31



/*	  Gatekeeper Priority Queue
 *	=================================
 *
 *
 * Gatekeeper is an open source DoS defense software which sends traffic based   * on an assigned priority for the client's requeust. Assigning priorities to    * packets enables us to give low priority to clients who quickly send many      * requests, so  that we can service legitimate clients (who typically send      * requests more slowly). The DoS scenario is when assigning low priorities      * helps block out malicious senders, who could otherwise overwhelm Gatekeeper   * with a very high number of requests, denying service to the requests of 
 * legitimate users.
 *
 *
 * To assign priority to packet, Gatekeeper uses the six bits of the DSCP field, * as it is a sufficient and convenient way to limit the maximum number of       * priorities we'd like to deal with. Additionally, using the DSCP field also    * allows us to more easily use tools like iptables and tc, which already        * understand fields in the IP header. 
 *
 *
 * Although the DSCP field is usually used to specify DiffServe traffic 
 * classifcation options, it is NOT used for that intent here. 
 *
 *
 *
 *   The Gatekeper standalone codebase is found here: 
 *	          
 *          https://github.com/AltraMayor/gatekeeper
 *
 *
 */


struct gkprioq_sched_data {
/* Parameters */
	u32 max_limit;

/*Variables*/
	struct Qdisc *prio_array[MAX_PRIORITY + 1];
	u16 last_dropped_prio;
	u16 highest_prio;
	u32 init_limit;
};

static inline u32 calc_alloc_len(const struct gkprioq_sched_data *q)
{
	u32 total_alloc_len = 0;
	int prio;
	
	for (prio = 0; prio < MAX_PRIORITY + 1; prio++) 
		total_alloc_len += (q->prio_array[prio])->limit;

	return total_alloc_len;
}

static inline u16 calc_new_high_prio(const struct gkprioq_sched_data *q)
{
	int prio;

	if (q->highest_prio > (HALF_MAX_PRIORITY + 1)) {
		for (prio = q->highest_prio - 1; prio > HALF_MAX_PRIORITY + 1; 
		                                 prio--) {
			if ((q->prio_array[prio])->q.qlen > 0)
				return prio;
		}
	}

	if ((q->prio_array[0])->q.qlen > 0) /*Treating as best effort queue*/
		return 0;

	for (prio = HALF_MAX_PRIORITY + 1; prio > 0; prio--) {
		if ((q->prio_array[prio])->q.qlen > 0)
			return prio;
	}

	return 0; /*GK queue is empty, return default highest priority setting*/

}

static int gkprioq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			   struct sk_buff **to_free)
{
	struct Qdisc *your_queue;
	int prio, ret, err, wlen, gk_len;
	u16 your_prio; 

	struct gkprioq_sched_data *q = qdisc_priv(sch);
	wlen = skb_network_offset(skb);

	switch(tc_skb_protocol(skb)) {
	case htons(ETH_P_IP):
		wlen += sizeof(struct iphdr);
		if (!pskb_may_pull(skb, wlen) || 
		    skb_try_make_writable(skb, wlen))
			goto drop;

		skb->tc_index = ipv4_get_dsfield(ip_hdr(skb))
			& ~INET_ECN_MASK;
		break;

	case htons(ETH_P_IPV6):
		wlen += sizeof(struct ipv6hdr);
		if (!pskb_may_pull(skb, wlen) || 
		    skb_try_make_writable(skb, wlen))
			goto drop;

		skb->tc_index = ipv6_get_dsfield(ipv6_hdr(skb))
			& ~INET_ECN_MASK;
		break;

	default: 
		skb->tc_index = 0;
		break;
	}

	your_prio = skb->tc_index;  /*DSCP field set as priority*/

	if (your_prio > q->highest_prio) /*Checking if a new highest priority*/	 	q->highest_prio = your_prio;
			
	your_queue = q->prio_array[your_prio];

	gk_len = calc_alloc_len(q);
	if (gk_len < q->max_limit) {
		err = fifo_set_limit(your_queue, 
				    your_queue->limit + q->init_limit);
		if (err) 
			return err;
	
		q->init_limit += 1; /* Fast forward resource allocation*/
	
		ret = qdisc_enqueue(skb, your_queue, to_free);
		if (ret != NET_XMIT_SUCCESS) {
			if (net_xmit_drop_count(ret))
				qdisc_qstats_drop(sch);
		return ret;
		}

		qdisc_qstats_backlog_inc(sch, skb);
		sch->q.qlen++;
		return NET_XMIT_SUCCESS;

	} else if (your_prio == (0 || 1) && your_queue->limit > 0) {
	
		qdisc_drop(skb, sch, to_free);	
	
		/* Priority 0 queue is the default case queue and is not allowed 		 * to borrow or be borrowed from. It is treated as a best effort 		 * queue. Priority 1 queue is the least priority and so can't		         * borrow from anyone.  
		 */
	
		qdisc_qstats_backlog_inc(sch, skb);
		sch->q.qlen++;
		return NET_XMIT_SUCCESS;

	} else {

	/* Queues need to borrow resources from other queues */	
		
	if (your_queue->q.qlen == your_queue->limit && your_queue->limit > 0) {

	prio = 1;

	while (q->prio_array[prio]->limit == 0)
		prio++;

	if((q->prio_array[prio])->q.qlen > 0) {
		__qdisc_queue_drop_head(q->prio_array[prio], 
					&(q->prio_array[prio])->q, to_free);	
		qdisc_qstats_drop(sch);
	}

	err = fifo_set_limit(q->prio_array[prio], 
			    (q->prio_array[prio])->limit - 1);
	if (err)
		return err;
	

	err = fifo_set_limit(your_queue, your_queue->limit + 1);
	if (err) 
		return err;
	
	ret = qdisc_enqueue(skb, your_queue, to_free);
	if (ret != NET_XMIT_SUCCESS) {
		if (net_xmit_drop_count(ret))
			qdisc_qstats_drop(sch);
		return ret;
	}

	qdisc_qstats_backlog_inc(sch, skb);
	sch->q.qlen++;
	return NET_XMIT_SUCCESS;

        }

	if (your_queue->limit == 0) {
		if (your_prio == 1 ||  
		   (q->prio_array[your_prio + 1])->limit == 0) 
			goto done;
	}

	/* Required priority queue is completey borrowed from and is not able 
	 * to borrow either. No choice but to drop packet now.
	 */

	ret = qdisc_enqueue(skb, your_queue, to_free);
	if (ret != NET_XMIT_SUCCESS) {
		if (net_xmit_drop_count(ret))
			qdisc_qstats_drop(sch);
		return ret;
	}
	
	qdisc_qstats_backlog_inc(sch, skb);
	sch->q.qlen++;
	return NET_XMIT_SUCCESS;	

	}

drop:
	qdisc_drop(skb, sch, to_free);
	return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
done:
	q->last_dropped_prio = your_prio;
	ret = qdisc_drop(skb, sch, to_free);
	return ret;

}

static struct sk_buff *gkprioq_dequeue(struct Qdisc *sch)
{
	struct gkprioq_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	int err;
	

	skb = qdisc_dequeue_head(q->prio_array[q->highest_prio]);

	if (skb) {
		if (q->last_dropped_prio != -1) {
			err = fifo_set_limit(q->prio_array[q->highest_prio], 
				   (q->prio_array[q->highest_prio])->limit - 1);
			if (err)
				pr_warn_once("Something is wrong!");
			
			/* Donate resources to priority queue whose last packet 			 * was dropped because of resource unavailability then.
	                 */

			err = fifo_set_limit(q->prio_array[q->last_dropped_prio]			     ,(q->prio_array[q->last_dropped_prio])->limit + 1);

			if (err)
				pr_warn_once("Something is wrong!");
	
		}

		goto done; 
	}

	return NULL;

done:
	if ((q->prio_array[q->highest_prio])->q.qlen > 0)
		return skb;

	q->highest_prio = calc_new_high_prio(q); 
	return skb;

}

static int gkprioq_init(struct Qdisc *sch, struct nlattr *opt)
{
	int prio;
	struct gkprioq_sched_data *q = qdisc_priv(sch);
	struct Qdisc *pfifo_q;

	if (opt == NULL) 
		 q->max_limit = qdisc_dev(sch)->tx_queue_len; 
	else {
		struct tc_gkprioq_qopt *ctl = nla_data(opt);

		if(nla_len(opt) < sizeof(*ctl))
			return -EINVAL;

		q->max_limit = ctl->limit;
	}
	
	q->init_limit = 1;

	for(prio = 0; prio <= 1; prio++) {
		pfifo_q = fifo_create_dflt(sch, &pfifo_qdisc_ops, 
					q->max_limit/(MAX_PRIORITY + 1));
		if (IS_ERR(pfifo_q)) 
			return PTR_ERR(pfifo_q);
		q->prio_array[prio] = pfifo_q;
	}

	for(prio = 2; prio < MAX_PRIORITY + 1; prio++) {
		pfifo_q = fifo_create_dflt(sch, &pfifo_qdisc_ops, 
						q->init_limit);
		if (IS_ERR(pfifo_q)) 
			return PTR_ERR(pfifo_q);
		q->prio_array[prio] = pfifo_q;
	}

	/* Saving resources now and deploying on the fly allocation in order to 	 * avoid under utilization of available resources
	 */

	q->last_dropped_prio = -1;
	q->highest_prio = 0; 
	return 0;

}

static int gkprioq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tc_gkprioq_qopt opt = {.limit = sch->limit};
	
	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	return -1;
}

static void gkprioq_reset(struct Qdisc *sch)
{
	int prio;
	struct gkprioq_sched_data *q = qdisc_priv(sch);

	for (prio = 0; prio < MAX_PRIORITY + 1; prio++) 
		qdisc_reset(q->prio_array[prio]);	

	sch->qstats.backlog = 0;
	q->init_limit = 1;
	q->last_dropped_prio = -1;
	q->highest_prio = 0;
}

static void gkprioq_destroy(struct Qdisc *sch)
{
	int prio;
	struct gkprioq_sched_data *q = qdisc_priv(sch);

	for (prio = 0; prio < MAX_PRIORITY + 1; prio++)
		qdisc_destroy(q->prio_array[prio]);
}

struct Qdisc_ops gkprioq_qdisc_ops __read_mostly = {
	.id		=	"gkprioq",
	.priv_size	=	sizeof(struct gkprioq_sched_data),
	.enqueue	=	gkprioq_enqueue,
	.dequeue	=	gkprioq_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	gkprioq_init,
	.reset		=	gkprioq_reset,
	.change		=	gkprioq_init,
	.dump		=	gkprioq_dump,
	.destroy 	=	gkprioq_destroy,
	.owner		=	THIS_MODULE,
};

static int __init gkprioq_module_init(void)
{
	return register_qdisc(&gkprioq_qdisc_ops);
}

static void __exit gkprioq_module_exit(void)
{
	unregister_qdisc(&gkprioq_qdisc_ops);
}

module_init(gkprioq_module_init)
module_exit(gkprioq_module_exit)

MODULE_LICENSE("GPL");
