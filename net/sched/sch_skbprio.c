/*
 * net/sched/sch_skbprio.c  SKB Priority Queue.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Nishanth Devarajan, <ndev2021@gmail.com>
 *		Cody Doucette, <doucette@bu.edu>
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


/*	  SKB Priority Queue
 *	=================================
 *
 * This qdisc schedules a packet according to skb->priority, where a higher
 * value places the packet closer to the exit of the queue. When the queue is
 * full, the lowest priority packet in the queue is dropped to make room for
 * the packet to be added if it has higher priority. If the packet to be added
 * has lower priority than all packets in the queue, it is dropped.
 *
 * Without the SKB priority queue, queue length limits must be imposed
 * for individual queues, and there is no easy way to enforce a global queue
 * length limit across all priorities. With the SKBprio queue, a global
 * queue length limit can be enforced while not restricting the queue lengths
 * of individual priorities.
 *
 * This is especially useful for a denial-of-service defense system like
 * Gatekeeper, which prioritizes packets in flows that demonstrate expected
 * behavior of legitimate users. The queue is flexible to allow any number
 * of packets of any priority up to the global limit of the scheduler
 * without risking resource overconsumption by a flood of low priority packets.
 *
 * The Gatekeeper codebase is found here:
 *
 *		https://github.com/AltraMayor/gatekeeper
 */

struct skbprio_sched_data {
	/* Parameters. */
	u32 max_limit;

	/* Queue state. */
	struct sk_buff_head qdiscs[SKBPRIO_MAX_PRIORITY];
	struct gnet_stats_queue qstats[SKBPRIO_MAX_PRIORITY];
	u16 highest_prio;
	u16 lowest_prio;
};

static u16 calc_new_high_prio(const struct skbprio_sched_data *q)
{
	int prio;

	for (prio = q->highest_prio - 1; prio >= q->lowest_prio; prio--) {
		if (!skb_queue_empty(&q->qdiscs[prio]))
			return prio;
	}

	/* SKB queue is empty, return 0 (default highest priority setting). */
	return 0;
}

static u16 calc_new_low_prio(const struct skbprio_sched_data *q)
{
	int prio;

	for (prio = q->lowest_prio + 1; prio <= q->highest_prio; prio++) {
		if (!skb_queue_empty(&q->qdiscs[prio]))
			return prio;
	}

	/* SKB queue is empty, return SKBPRIO_MAX_PRIORITY - 1
	 * (default lowest priority setting).
	 */
	return SKBPRIO_MAX_PRIORITY - 1;
}

static int skbprio_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	const unsigned int max_priority = SKBPRIO_MAX_PRIORITY - 1;
	struct skbprio_sched_data *q = qdisc_priv(sch);
	struct sk_buff_head *qdisc;
	struct sk_buff_head *lp_qdisc;
	struct sk_buff *to_drop;
	u16 prio, lp;

	/* Obtain the priority of @skb. */
	prio = min(skb->priority, max_priority);

	qdisc = &q->qdiscs[prio];
	if (sch->q.qlen < q->max_limit) {
		__skb_queue_tail(qdisc, skb);
		qdisc_qstats_backlog_inc(sch, skb);
		q->qstats[prio].backlog += qdisc_pkt_len(skb);

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
	if (prio <= lp) {
		q->qstats[prio].drops++;
		return qdisc_drop(skb, sch, to_free);
	}

	/* Drop the packet at the tail of the lowest priority qdisc. */
	lp_qdisc = &q->qdiscs[lp];
	to_drop = __skb_dequeue_tail(lp_qdisc);
	BUG_ON(!to_drop);
	qdisc_qstats_backlog_dec(sch, to_drop);
	qdisc_drop(to_drop, sch, to_free);

	q->qstats[lp].backlog -= qdisc_pkt_len(to_drop);
	q->qstats[lp].drops++;

	__skb_queue_tail(qdisc, skb);
	qdisc_qstats_backlog_inc(sch, skb);
	q->qstats[prio].backlog += qdisc_pkt_len(skb);

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

	return NET_XMIT_CN;
}

static struct sk_buff *skbprio_dequeue(struct Qdisc *sch)
{
	struct skbprio_sched_data *q = qdisc_priv(sch);
	struct sk_buff_head *hpq = &q->qdiscs[q->highest_prio];
	struct sk_buff *skb = __skb_dequeue(hpq);

	if (unlikely(!skb))
		return NULL;

	sch->q.qlen--;
	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	q->qstats[q->highest_prio].backlog -= qdisc_pkt_len(skb);

	/* Update highest priority field. */
	if (skb_queue_empty(hpq)) {
		if (q->lowest_prio == q->highest_prio) {
			BUG_ON(sch->q.qlen);
			q->highest_prio = 0;
			q->lowest_prio = SKBPRIO_MAX_PRIORITY - 1;
		} else {
			q->highest_prio = calc_new_high_prio(q);
		}
	}
	return skb;
}

static int skbprio_change(struct Qdisc *sch, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	struct skbprio_sched_data *q = qdisc_priv(sch);
	struct tc_skbprio_qopt *ctl = nla_data(opt);
	const unsigned int min_limit = 1;

	if (ctl->limit == (typeof(ctl->limit))-1)
		q->max_limit = max(qdisc_dev(sch)->tx_queue_len, min_limit);
	else if (ctl->limit < min_limit ||
		ctl->limit > qdisc_dev(sch)->tx_queue_len)
		return -EINVAL;
	else
		q->max_limit = ctl->limit;

	return 0;
}

static int skbprio_init(struct Qdisc *sch, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	struct skbprio_sched_data *q = qdisc_priv(sch);
	const unsigned int min_limit = 1;
	int prio;

	/* Initialise all queues, one for each possible priority. */
	for (prio = 0; prio < SKBPRIO_MAX_PRIORITY; prio++)
		__skb_queue_head_init(&q->qdiscs[prio]);

	memset(&q->qstats, 0, sizeof(q->qstats));
	q->highest_prio = 0;
	q->lowest_prio = SKBPRIO_MAX_PRIORITY - 1;
	if (!opt) {
		q->max_limit = max(qdisc_dev(sch)->tx_queue_len, min_limit);
		return 0;
	}
	return skbprio_change(sch, opt, extack);
}

static int skbprio_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct skbprio_sched_data *q = qdisc_priv(sch);
	struct tc_skbprio_qopt opt;

	opt.limit = q->max_limit;

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		return -1;

	return skb->len;
}

static void skbprio_reset(struct Qdisc *sch)
{
	struct skbprio_sched_data *q = qdisc_priv(sch);
	int prio;

	sch->qstats.backlog = 0;
	sch->q.qlen = 0;

	for (prio = 0; prio < SKBPRIO_MAX_PRIORITY; prio++)
		__skb_queue_purge(&q->qdiscs[prio]);

	memset(&q->qstats, 0, sizeof(q->qstats));
	q->highest_prio = 0;
	q->lowest_prio = SKBPRIO_MAX_PRIORITY - 1;
}

static void skbprio_destroy(struct Qdisc *sch)
{
	struct skbprio_sched_data *q = qdisc_priv(sch);
	int prio;

	for (prio = 0; prio < SKBPRIO_MAX_PRIORITY; prio++)
		__skb_queue_purge(&q->qdiscs[prio]);
}

static struct Qdisc *skbprio_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long skbprio_find(struct Qdisc *sch, u32 classid)
{
	return 0;
}

static int skbprio_dump_class(struct Qdisc *sch, unsigned long cl,
			     struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int skbprio_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				   struct gnet_dump *d)
{
	struct skbprio_sched_data *q = qdisc_priv(sch);
	if (gnet_stats_copy_queue(d, NULL, &q->qstats[cl - 1],
		q->qstats[cl - 1].qlen) < 0)
		return -1;
	return 0;
}

static void skbprio_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	unsigned int i;

	if (arg->stop)
		return;

	for (i = 0; i < SKBPRIO_MAX_PRIORITY; i++) {
		if (arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, i + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static const struct Qdisc_class_ops skbprio_class_ops = {
	.leaf		=	skbprio_leaf,
	.find		=	skbprio_find,
	.dump		=	skbprio_dump_class,
	.dump_stats	=	skbprio_dump_class_stats,
	.walk		=	skbprio_walk,
};

static struct Qdisc_ops skbprio_qdisc_ops __read_mostly = {
	.cl_ops		=	&skbprio_class_ops,
	.id		=	"skbprio",
	.priv_size	=	sizeof(struct skbprio_sched_data),
	.enqueue	=	skbprio_enqueue,
	.dequeue	=	skbprio_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.init		=	skbprio_init,
	.reset		=	skbprio_reset,
	.change		=	skbprio_change,
	.dump		=	skbprio_dump,
	.destroy	=	skbprio_destroy,
	.owner		=	THIS_MODULE,
};

static int __init skbprio_module_init(void)
{
	return register_qdisc(&skbprio_qdisc_ops);
}

static void __exit skbprio_module_exit(void)
{
	unregister_qdisc(&skbprio_qdisc_ops);
}

module_init(skbprio_module_init)
module_exit(skbprio_module_exit)

MODULE_LICENSE("GPL");
