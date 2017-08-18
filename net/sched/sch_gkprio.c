/*
 * net/sched/sch_gkprio.c  Gatekeeper Priority Queue.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Nishanth Devarajan, <ndev_2021@gmail.com>
 *	        original idea by Michel Machado, Cody Doucette, and Qiaobin Fu
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
#include <net/inet_ecn.h>

/* Packets are assigned priorities [0, 63] due to the IP DSCP field limits. */
#define GKPRIO_MAX_PRIORITY 64

/*	  Gatekeeper Priority Queue
 *	=================================
 *
 * This qdisc schedules a packet according to the value (0-63) of its DSCP
 * (IPv4) or DS (IPv6) field, where a higher value places the packet closer
 * to the exit of the queue. Non-IP packets are assigned a default priority
 * specified to GKPRIO; if none is specified, default priority is set
 * to 0. When the queue is full, the lowest priority packet in the queue is
 * dropped to make room for the packet to be added if it has higher priority.
 * If the packet to be added has lower priority than all packets in the queue,
 * it is dropped.
 *
 * Without the Gatekeeper priority queue, queue length limits must be imposed
 * for individual queues, and there is no easy way to enforce a global queue
 * length limit across all priorities. With the Gatekeeper queue, a global
 * queue length limit can be enforced while not restricting the queue lengths
 * of individual priorities.
 *
 * This is especially useful for a denial-of-service defense system; like
 * Gatekeeper, which prioritizes packets in flows that demonstrate expected
 * behavior of legitimate users. The queue is flexible to allow any number
 * of packets of any priority up to the global limit of the scheduler
 * without risking resource overconsumption by a flood of low priority packets.
 *
 * The Gatekeper standalone codebase is found here:
 *
 *		https://github.com/AltraMayor/gatekeeper
 */

struct gkprio_sched_data {
	/* Parameters. */
	u32 max_limit;
	u16 noip_dfltp;

	/* Queue state. */
	struct sk_buff_head qdiscs[GKPRIO_MAX_PRIORITY];
	u16 highest_prio;
	u16 lowest_prio;
};

static u16 calc_new_high_prio(const struct gkprio_sched_data *q)
{
	int prio;

	for (prio = q->highest_prio - 1; prio >= q->lowest_prio; prio--) {
		if (!skb_queue_empty(&q->qdiscs[prio]))
			return prio;
	}

	/* GK queue is empty, return 0 (default highest priority setting). */
	return 0;
}

static u16 calc_new_low_prio(const struct gkprio_sched_data *q)
{
	int prio;

	for (prio = q->lowest_prio + 1; prio <= q->highest_prio; prio++) {
		if (!skb_queue_empty(&q->qdiscs[prio]))
			return prio;
	}

	/* GK queue is empty, return GKPRIO_MAX_PRIORITY - 1
	 * (default lowest priority setting).
	 */
	return GKPRIO_MAX_PRIORITY - 1;
}

static int gkprio_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	struct gkprio_sched_data *q = qdisc_priv(sch);
	struct sk_buff_head *qdisc;
	struct sk_buff_head *lp_qdisc;
	struct sk_buff *to_drop;
	int wlen;
	u16 prio, lp;

	/* Obtain the priority of @skb. */
	wlen = skb_network_offset(skb);
	switch (tc_skb_protocol(skb)) {
	case htons(ETH_P_IP):
		wlen += sizeof(struct iphdr);
		if (!pskb_may_pull(skb, wlen))
			goto drop;
		prio = ipv4_get_dsfield(ip_hdr(skb)) >> 2;
		break;

	case htons(ETH_P_IPV6):
		wlen += sizeof(struct ipv6hdr);
		if (!pskb_may_pull(skb, wlen))
			goto drop;
		prio = ipv6_get_dsfield(ipv6_hdr(skb)) >> 2;
		break;

	default:
		prio = q->noip_dfltp;
		break;
	}

	qdisc = &q->qdiscs[prio];

	if (sch->q.qlen < q->max_limit) {
		__skb_queue_tail(qdisc, skb);
		qdisc_qstats_backlog_inc(sch, skb);

		/* Check to update highest and lowest priorities. */
		if (prio > q->highest_prio)
			q->highest_prio = prio;

		if (prio < q->lowest_prio)
			q->lowest_prio = prio;

		sch->q.qlen++;
		return NET_XMIT_SUCCESS;
	}

	/* If this packet has the lowest priority, drop it. */
	lp = q->lowest_prio;
	if (prio <= lp)
		return qdisc_drop(skb, sch, to_free);

	/* Drop the packet at the tail of the lowest priority qdisc. */
	lp_qdisc = &q->qdiscs[lp];
	to_drop = __skb_dequeue_tail(lp_qdisc);
	BUG_ON(!to_drop);
	qdisc_qstats_backlog_dec(sch, to_drop);
	qdisc_drop(to_drop, sch, to_free);

	__skb_queue_tail(qdisc, skb);
	qdisc_qstats_backlog_inc(sch, skb);

	/* Check to update highest and lowest priorities. */
	if (skb_queue_empty(lp_qdisc)) {
		if (q->lowest_prio == q->highest_prio) {
			BUG_ON(sch->q.qlen);
			q->lowest_prio = prio;
			q->highest_prio = prio;
		} else {
			q->lowest_prio = calc_new_low_prio(q);
		}
	}

	if (prio > q->highest_prio)
		q->highest_prio = prio;

	return NET_XMIT_SUCCESS;
drop:
	qdisc_drop(skb, sch, to_free);
	return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
}

static struct sk_buff *gkprio_dequeue(struct Qdisc *sch)
{
	struct gkprio_sched_data *q = qdisc_priv(sch);
	struct sk_buff_head *hpq = &q->qdiscs[q->highest_prio];
	struct sk_buff *skb = __skb_dequeue(hpq);

	if (unlikely(!skb))
		return NULL;

	sch->q.qlen--;
	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	/* Update highest priority field. */
	if (skb_queue_empty(hpq)) {
		if (q->lowest_prio == q->highest_prio) {
			BUG_ON(sch->q.qen);
			q->highest_prio = 0;
			q->lowest_prio = GKPRIO_MAX_PRIORITY - 1;
		} else {
			q->highest_prio = calc_new_high_prio(q);
		}
	}
	return skb;
}

static int gkprio_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct gkprio_sched_data *q = qdisc_priv(sch);
	int prio;

	/* Initialise all queues, one for each possible priority. */
	for (prio = 0; prio < GKPRIO_MAX_PRIORITY; prio++)
		__skb_queue_head_init(&q->qdiscs[prio]);

	q->highest_prio = 0;
	q->lowest_prio = GKPRIO_MAX_PRIORITY - 1;
	if (!opt) {
		q->max_limit = max(qdisc_dev(sch)->tx_queue_len, 1);
		q->noip_dfltp = 0;
		return 0;
	}
	return gkprio_change(sch, opt);
}

static int gprio_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct gkprio_sched_data *q = qdisc_priv(sch);
	struct tc_gkprio_qopt *ctl = nla_data(opt);

	if (nla_len(opt) < sizeof(*ctl))
		return -EINVAL;

	if (ctl->limit == (typeof(ctl->limit))-1)
		q->max_limit = max(qdisc_dev(sch)->tx_queue_len, 1);
	else if (ctl->limit < 1 || ctl->limit > qdisc_dev(sch)->tx_queue_len)
		return -EINVAL;
	else
		q->max_limit = ctl->limit;

	if (ctl->dfltp == (typeof(ctl->dfltp))-1)
		q->noip_dfltp = 0;
	else if (ctl->dfltp >= GKPRIO_MAX_PRIORITY)
		return -EINVAL;
	else
		q->noip_dfltp = ctl->dfltp;

	return 0;
}

static int gkprio_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct gkprio_sched_data *q = qdisc_priv(sch);
	struct tc_gkprio_qopt opt;

	opt.limit = q->max_limit;
	opt.dfltp = q->noip_dfltp;
	opt.highest_prio = q->highest_prio;
	opt.lowest_prio = q->lowest_prio;

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		return -1;

	return skb->len;
}

static void gkprio_reset(struct Qdisc *sch)
{
	struct gkprio_sched_data *q = qdisc_priv(sch);
	int prio;

	sch->qstats.backlog = 0;
	sch->q.qlen = 0;

	for (prio = 0; prio < GKPRIO_MAX_PRIORITY; prio++)
		__skb_queue_purge(&q->qdiscs[prio]);
	q->highest_prio = 0;
	q->lowest_prio = GKPRIO_MAX_PRIORITY - 1;
}

static void gkprio_destroy(struct Qdisc *sch)
{
	struct gkprio_sched_data *q = qdisc_priv(sch);
	int prio;

	for (prio = 0; prio < GKPRIO_MAX_PRIORITY; prio++)
		__skb_queue_purge(&q->qdiscs[prio]);
}

struct Qdisc_ops gkprio_qdisc_ops __read_mostly = {
	.id		=	"gkprio",
	.priv_size	=	sizeof(struct gkprio_sched_data),
	.enqueue	=	gkprio_enqueue,
	.dequeue	=	gkprio_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	gkprio_init,
	.reset		=	gkprio_reset,
	.change		=	gkprio_change,
	.dump		=	gkprio_dump,
	.destroy	=	gkprio_destroy,
	.owner		=	THIS_MODULE,
};

static int __init gkprio_module_init(void)
{
	return register_qdisc(&gkprio_qdisc_ops);
}

static void __exit gkprio_module_exit(void)
{
	unregister_qdisc(&gkprio_qdisc_ops);
}

module_init(gkprio_module_init)
module_exit(gkprio_module_exit)

MODULE_LICENSE("GPL");
