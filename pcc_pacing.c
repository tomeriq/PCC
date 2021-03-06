/*
 * TCP PCC: Performence-oriented Congestion Control.
 * This is a congestion control module for TCP, which suggests a goal-based
 * approach for setting the tx pacing rate. 
 * This module is build on top of Google's BBR kernel patches.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>

#define FIXEDPT_BITS (64)
#define FIXEDPT_WBITS (32)
#include "fixedptc.h"


#define DEBUG

#ifdef DEBUG
#define DBG_PRINT(...) printk(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif

#define DEFAULT_RATE_LIMIT (2000 * (1<<10))
#define SUPPORTED_SESSIONS_NUMBER (1024)
#define LARGE_CWND (20000000)
#define NUMBER_OF_INTERVALS (30)
#define PREV_MONITOR(index) ((index) > 0 ? ((index) - 1) : (NUMBER_OF_INTERVALS - 1))
#define DEFAULT_TTL 1000
#define MINIMUM_RATE (800000)
#define INITIAL_RATE (1000000)

static void on_monitor_start(struct sock *sk, int index);

typedef enum {
	PCC_STATE_START = 0,
	PCC_STATE_DECISION_MAKING_1,
	PCC_STATE_DECISION_MAKING_2,
	PCC_STATE_DECISION_MAKING_3,
	PCC_STATE_DECISION_MAKING_4,
	PCC_STATE_WAIT_FOR_DECISION,
	PCC_STATE_RATE_ADJUSTMENT,
} pcc_state_t;

struct monitor {
	u8 valid;						//1 if the monitor interval is still sending or receiving acks
	u8 decision_making_id;			// the ID of monitor interval in the decision making quartet
	pcc_state_t state;				//state at the start of the monitor interval
	unsigned long end_time;			//usecs until sending ends
	u32 snd_start_seq;				//first sequence to send in the monitor interval
	u32 snd_end_seq;				//last sequence sent
	u32 last_acked_seq;				//last sequence we know what happened (can be greater than snd_end_seq)
	int segments_sent;				//segments sent in the monitor interval
	u32 bytes_lost;					//amount of bytes lost due to sacks
	u64 rate;						//rate limit of the monitor
	s64 utility;					//calculated utility of the monitor
	u32 rtt;						//last rtt captured while this monitor was active
	struct timespec start_time;		//timestamp of the start of the monitor
	u64 actual_rate;				//actual rate data was sent in the monitor
};


struct pccdata {
	struct monitor monitor_intervals[NUMBER_OF_INTERVALS];		//all monitor intervals
	struct monitor decision_making_intervals[4];				//monitor intervals related to decision making will be copied here
	u8 current_interval;										//index of the current (sending) interval
	pcc_state_t state;											//current state
	u64 snd_count;												//number of segments sent for the start of the connection
	u32 last_rtt;												//last rtt measured
	u64 next_rate;												//next base rate to send in
	int direction;												//direction to advance rate in (-1 for lowering the rate, 1 for raising it)
	int decision_making_attempts;								//number of decision making attempts without a clear decision
	int rate_adjustment_tries;									//number of monitor intervals with the rate adjustment state
	int decision_directions[4];									//for decision making shuffle
	u64 last_actual_rate;										//last actual rate sent data in
};



/* This struct is in the Congestion Control reserved space of the TCP socket */
struct pcctcp {
	struct pccdata* pcc;
};

static void shuffle_decision_directions(struct sock *sk)
{
	u32 random;
	u8 ups = 0;
	struct pcctcp *ca = inet_csk_ca(sk);

	get_random_bytes(&random, sizeof(random));
	if (random % 2 == 0) {
		ca->pcc->decision_directions[0] = 1;
		ups++;
	} else {
		ca->pcc->decision_directions[0] = -1;
	}
	get_random_bytes(&random, sizeof(random));
	if (random % 2 == 0) {
		ca->pcc->decision_directions[1] = 1;
		ups++;
	} else {
		ca->pcc->decision_directions[1] = -1;
	}

	if (ups == 2) {
		ca->pcc->decision_directions[2] = -1;
		ca->pcc->decision_directions[3] = -1;
		return;
	} else if (ups == 0) {
		ca->pcc->decision_directions[2] = 1;
		ca->pcc->decision_directions[3] = 1;
		return;
	}

	get_random_bytes(&random, sizeof(random));
	if (random % 2 == 0) {
		ca->pcc->decision_directions[2] = 1;
		ups++;
	} else {
		ca->pcc->decision_directions[2] = -1;
	}

	if (ups == 3) {
		ca->pcc->decision_directions[3] = -1;
	} else if (ups == 1) {
		ca->pcc->decision_directions[3] = 1;
	}
}

/** inits a monitor interval and sets it as inactive */
static void init_monitor(struct monitor * mon, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct pcctcp *ca = inet_csk_ca(sk);

	mon->valid = 0;
	mon->start_time = current_kernel_time();
	mon->end_time = ((tp->srtt_us >> 3) * 4 )/ 3;
	mon->snd_start_seq = tp->snd_nxt;
	mon->snd_end_seq = 0;
	mon->last_acked_seq = tp->snd_nxt;
	mon->segments_sent = 0;
	mon->bytes_lost = 0;
	mon->rate = 0;
	mon->utility = 0;
	mon->decision_making_id = 0;
	mon->rtt = ca->pcc->last_rtt;
	mon->state = ca->pcc->state;

	DBG_PRINT("init monitor %d. end time is %u\n", ca->pcc->current_interval, mon->end_time);
}

static void init_pcc_struct(struct sock *sk, struct pcctcp *ca)
{
	if (ca->pcc != NULL) {
		return;
	}

	ca->pcc = kmalloc(sizeof(struct pccdata), GFP_KERNEL);
	if (!ca->pcc) {
		DBG_PRINT(KERN_ERR "could not allocate pcc data\n");
		return;
	}

	DBG_PRINT("[PCC] initialized pcc struct");
	memset(ca->pcc, 0, sizeof(struct pccdata));
	ca->pcc->next_rate = INITIAL_RATE;
	ca->pcc->last_actual_rate = INITIAL_RATE / 2;
	sk->sk_pacing_rate = INITIAL_RATE;
	init_monitor(&(ca->pcc->monitor_intervals[0]), sk);
	on_monitor_start(sk, ca->pcc->current_interval);
	ca->pcc->monitor_intervals[ca->pcc->current_interval].valid = 1;

}



/** updates the segments sent of the current interval from the last call to this function */
static void check_if_sent(struct sock *sk)
{
	struct pcctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct monitor * mon = ca->pcc->monitor_intervals + ca->pcc->current_interval;

	if (ca->pcc->snd_count == tp->data_segs_out) {
		return;
	}
	
	mon->segments_sent += (tp->data_segs_out - ca->pcc->snd_count);
	ca->pcc->snd_count = tp->data_segs_out;
	mon->snd_end_seq = tp->snd_nxt;

}

/* calculates the utility of a monitor */
static s64 calc_utility(struct monitor * mon, struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct pcctcp *ca = inet_csk_ca(sk);
	u64 sent = (mon->segments_sent) * tp->advmss;
	u64 length_us = mon->end_time + 1;
	fixedpt rate = fixedpt_mul(fixedpt_div(fixedpt_fromint(sent), fixedpt_fromint(length_us)), fixedpt_fromint(1000000));
	mon->actual_rate = rate >> FIXEDPT_FBITS;
	ca->pcc->last_actual_rate = rate >> FIXEDPT_FBITS;
	fixedpt p = fixedpt_div(fixedpt_fromint(mon->bytes_lost), (fixedpt_fromint(sent)));
	fixedpt utility;
	fixedpt time = fixedpt_div(fixedpt_fromint(length_us), fixedpt_rconst(1000000));

	if (mon->end_time == 0) {
		DBG_PRINT("BUG: monitor end time is 0\n");
	}
	if (sent < mon->bytes_lost) {
		DBG_PRINT("BUG: for some reason, lost more than sent\n");
	}

	if (rate >> FIXEDPT_WBITS > mon->rate) {
		DBG_PRINT("BUG: actual rate is much bigger than limited rate. length_us = %llu, sent = %llu\n", length_us, sent);
	}

	utility = (rate - (fixedpt_mul(rate, fixedpt_pow(FIXEDPT_ONE + p, fixedpt_rconst(2.5)) - FIXEDPT_ONE) ));
	//utility = mon->rate * 100 - mon->rate * ((sent + mon->bytes_lost) * (sent + mon->bytes_lost) * 100 / (sent * sent) - 100);
	//utility = mon->snd_end_seq - mon->snd_start_seq;
	//utility = fixedpt_div(fixedpt_fromint(mon->snd_end_seq - mon->snd_start_seq), time);
	//utility = (fixedpt_div(fixedpt_fromint(sent - mon->bytes_lost), time) - fixedpt_div(fixedpt_mul(fixedpt_rconst(20), fixedpt_fromint(mon->bytes_lost)), time));
	//utility = fixedpt_div(fixedpt_fromint(sent -mon->bytes_lost), time);
	
	utility = fixedpt_div(fixedpt_fromint(sent - mon->bytes_lost), time);
	utility = fixedpt_mul(utility, FIXEDPT_ONE - fixedpt_div(FIXEDPT_ONE, FIXEDPT_ONE + fixedpt_exp(fixedpt_mul(fixedpt_fromint(-100), fixedpt_div(fixedpt_fromint(mon->bytes_lost), fixedpt_fromint(sent)) - fixedpt_rconst(0.05))))) - fixedpt_div(fixedpt_fromint(mon->bytes_lost), time);
	rate = fixedpt_mul(fixedpt_div(fixedpt_fromint(sent), fixedpt_fromint(length_us)), fixedpt_rconst(1000000));
	DBG_PRINT("[PCC] calculating utility: rate (limit): %llu, rate (actual): %llu, sent (by sequence): %llu, lost: %u, time: %u, utility: %d, sent segements: %d, sent (by segments): %u, state: %d\n", mon->rate, rate >> FIXEDPT_WBITS, mon->snd_end_seq - mon->snd_start_seq, mon->bytes_lost, length_us, (s32)(utility >> FIXEDPT_WBITS), mon->segments_sent,  (mon->segments_sent) * tp->advmss, mon->state);

	return utility;
}

static void on_monitor_start(struct sock *sk, int index)
{
	struct pcctcp *ca = inet_csk_ca(sk);
	struct monitor * mon = ca->pcc->monitor_intervals + index;
	u64 rate = ca->pcc->next_rate;
	u8 should_update_base_rate = 0;

	DBG_PRINT("[PCC] raw rate is %llu (interval %d)\n", rate, index);
	switch (ca->pcc->state) {
		case PCC_STATE_START:
			//rate = ca->pcc->last_actual_rate * 2;
			rate *= 2;
			ca->pcc->next_rate = rate;
			should_update_base_rate = 1;
			DBG_PRINT("[PCC] in start state (interval %d)\n", index);
			break;
		case PCC_STATE_DECISION_MAKING_1:
			rate = rate + (ca->pcc->decision_making_attempts * 1 * (rate / 100));
			ca->pcc->state = PCC_STATE_DECISION_MAKING_2;
			mon->decision_making_id = 1;
			DBG_PRINT("[PCC] in DM 1 state (interval %d)\n", index);

			break;
		case PCC_STATE_DECISION_MAKING_2:
			rate = rate - (ca->pcc->decision_making_attempts * 1 * (rate / 100));
			ca->pcc->state = PCC_STATE_DECISION_MAKING_3;
			mon->decision_making_id = 2;
			DBG_PRINT("[PCC] in DM 2 state (interval %d)\n", index);
			break;
		case PCC_STATE_DECISION_MAKING_3:
			rate = rate + (ca->pcc->decision_making_attempts * 1 * (rate / 100));
			ca->pcc->state = PCC_STATE_DECISION_MAKING_4;
			mon->decision_making_id = 3;
			DBG_PRINT("[PCC] in DM 3 state (interval %d)\n", index);
			break;
		case PCC_STATE_DECISION_MAKING_4:
			rate = rate - (ca->pcc->decision_making_attempts * 1 * (rate / 100));
			ca->pcc->state = PCC_STATE_WAIT_FOR_DECISION;
			mon->decision_making_id = 4;
			DBG_PRINT("[PCC] in DM 4 state (interval %d)\n", index);
			break;
		case PCC_STATE_RATE_ADJUSTMENT:
			rate = rate + ((rate / 100) * ca->pcc->direction * ca->pcc->rate_adjustment_tries * 1);
			if ((ca->pcc->direction > 0 && rate < ca->pcc->next_rate) || (ca->pcc->direction < 0 && rate > ca->pcc->next_rate))
			{
				DBG_PRINT("[PCC] overflow in rate adjustment." \
					"rate came out as %llu, direction is %d, tries is: %d\n" \
					"addition is %d", rate, ca->pcc->direction, ca->pcc->rate_adjustment_tries, 
					((rate / 100) * ca->pcc->direction * ca->pcc->rate_adjustment_tries * 5));
				//overflow detected
				rate = ca->pcc->next_rate;
				ca->pcc->rate_adjustment_tries = 1;

			}
			should_update_base_rate = 1;
			ca->pcc->rate_adjustment_tries++;
			DBG_PRINT("[PCC] in rate adjustment state (interval %d)\n", index);
			break;
		case PCC_STATE_WAIT_FOR_DECISION:
			DBG_PRINT("[PCC] in wait for decision state (interval %d)\n", index);
			break;
	}

	rate = max_t(u64, rate, MINIMUM_RATE);

	DBG_PRINT("[PCC] rate is %llu (interval %d)\n", rate, index);

	if (rate != 0) {
		ca->pcc->monitor_intervals[index].rate = rate;
		if (should_update_base_rate) {
			ca->pcc->next_rate = rate;
		}
	}
}

static void make_decision(struct sock *sk, struct pccdata * pcc)
{
	if ((pcc->decision_making_intervals[0].utility > pcc->decision_making_intervals[1].utility) &&
		(pcc->decision_making_intervals[2].utility > pcc->decision_making_intervals[3].utility)) {
		pcc->next_rate = pcc->decision_making_intervals[0].rate;
		pcc->state = PCC_STATE_RATE_ADJUSTMENT;
		pcc->direction = 1;
		pcc->rate_adjustment_tries = 1;
		memset(pcc->decision_making_intervals, 0, sizeof(pcc->decision_making_intervals));
		pcc->decision_making_attempts = 0;

	} else if ((pcc->decision_making_intervals[0].utility < pcc->decision_making_intervals[1].utility) &&
		(pcc->decision_making_intervals[2].utility < pcc->decision_making_intervals[3].utility)) {
		pcc->next_rate = pcc->decision_making_intervals[1].rate;
		pcc->state = PCC_STATE_RATE_ADJUSTMENT;
		pcc->direction = -1;
		pcc->rate_adjustment_tries = 1;
		memset(pcc->decision_making_intervals, 0, sizeof(pcc->decision_making_intervals));
		pcc->decision_making_attempts = 0;

	} else {
		pcc->state = PCC_STATE_DECISION_MAKING_1;
		pcc->decision_making_attempts++;
	}
}

static inline u32 pcc_get_rate(struct sock * sk) 
{
	struct pcctcp *ca = inet_csk_ca(sk);
	return ca->pcc->monitor_intervals[ca->pcc->current_interval].rate;
}

/** called when a monitor's send period has ended and received ack for the last sent sequence */
static void on_monitor_end(struct sock *sk, int index)
{
	struct pcctcp *ca = inet_csk_ca(sk);
	struct monitor * mon = ca->pcc->monitor_intervals + index;
	struct monitor * prev_mon = ca->pcc->monitor_intervals + PREV_MONITOR(index);

	if (mon->segments_sent != 0 && mon->snd_end_seq != 0) {
		mon->utility = calc_utility(mon, sk);
		DBG_PRINT("got utility %lld for monitor interval %d\n", mon->utility, index);
	}

	/* first monitor interval in the connection */
	if (mon->state == PCC_STATE_START && prev_mon->snd_end_seq == 0) {
		return;
	}
	// if in start state or in rate adjustment state, and utility is worse than last monitor, go to decision making and restor last good rate
	if (mon->state != PCC_STATE_WAIT_FOR_DECISION && ca->pcc->snd_count > 3 && mon->utility < prev_mon->utility && ((ca->pcc->state == PCC_STATE_START) || ca->pcc->state == PCC_STATE_RATE_ADJUSTMENT)) {
		ca->pcc->state = PCC_STATE_DECISION_MAKING_1;
		ca->pcc->decision_making_attempts = 1;
		ca->pcc->next_rate = prev_mon->rate;
		if (mon->state == PCC_STATE_START) {
			ca->pcc->next_rate = prev_mon->actual_rate;
			DBG_PRINT("[PCC] end of start state, setting rate to %u\n", ca->pcc->next_rate);
		}
	}

	//if in decision making, copy this interval
	if (mon->decision_making_id != 0) {
		memcpy(ca->pcc->decision_making_intervals + mon->decision_making_id - 1, mon, sizeof(struct monitor));
	}

	//last interval of decision making ended, make a decision
	if (mon->decision_making_id == 4) {
		make_decision(sk, ca->pcc);
	}
	
}


static void on_interval_graceful_end(struct sock *sk, int index)
{
	struct pcctcp *ca = inet_csk_ca(sk);
	struct monitor * mon = ca->pcc->monitor_intervals + index;
	DBG_PRINT("[PCC] graceful end for monitor interval with seqs %u-%u and segments_sent %d and %u loss\n", mon->snd_start_seq, mon->snd_end_seq, mon->segments_sent, mon->bytes_lost);
	on_monitor_end(sk, index);
}

/** checks if current interval finished sending, and start a new if it did
	checks if any active intervals finished receiving acks and ends them if they did
**/
static void check_end_of_monitor_interval(struct sock *sk)
{
	u8 i;
	struct pcctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct monitor * mon = ca->pcc->monitor_intervals + ca->pcc->current_interval;
	struct timespec length = timespec_sub(current_kernel_time(), mon->start_time);
	u32 length_us = length.tv_sec * 1000000 + length.tv_nsec / 1000;

	//make sure monitor has sent at least 20 segments
	if (mon->segments_sent < 20) {
		while (length_us > mon->end_time) {
			mon->end_time += 50;
		}
	} else if ((mon->snd_start_seq != mon->snd_end_seq) && ((length_us > mon->end_time) )) {
		//current interval finished sending, start a new one
		DBG_PRINT("current monitor %d finished sending. end time should have been %u and was %u\n",ca->pcc->current_interval, mon->end_time, length_us);
		mon->end_time = length_us;
		ca->pcc->current_interval = (ca->pcc->current_interval + 1) % NUMBER_OF_INTERVALS;
		mon = ca->pcc->monitor_intervals + ca->pcc->current_interval;

		if (mon->valid) {
			DBG_PRINT(KERN_ERR "BUG: overrunning interval\n");
			mon->valid = 0;
		}
	}

	// go over all valid intervals and check if they finished receiving
	for (i = 0; i < NUMBER_OF_INTERVALS; i++) {
		struct monitor *loop_mon = ca->pcc->monitor_intervals + i;
		if (!loop_mon->valid) {
			continue;
		}
		length = timespec_sub(current_kernel_time(), loop_mon->start_time);
		length_us = length.tv_sec * 1000000 + length.tv_nsec / 1000;
		if (loop_mon->snd_start_seq != loop_mon->snd_end_seq && ((length_us > loop_mon->end_time)) && 
			!after(loop_mon->snd_end_seq, loop_mon->last_acked_seq)) {
			on_interval_graceful_end(sk, i);
			loop_mon->valid = 0;
		} 
	}

	//current monitor is invalid (started a new one probably) init it
	if (!mon->valid) {
		init_monitor(mon, sk);
		if (ca->pcc->next_rate == 0) {
			if (tp->advmss == 0 || ca->pcc->last_rtt == 0) {
				DBG_PRINT(KERN_INFO "[PCC] did not set rate as there is no mss or rtt");
			} else {
				//ca->pcc->next_rate = (2 * (tp->advmss)) / ca->pcc->last_rtt;
			}
		} 
		on_monitor_start(sk, ca->pcc->current_interval);
		DBG_PRINT(KERN_INFO "[PCC] setting rate:%u (%u Kbps) was %u, max is %u\n", pcc_get_rate(sk), (pcc_get_rate(sk) * 8) / 1000, sk->sk_pacing_rate, sk->sk_max_pacing_rate);
		sk->sk_pacing_rate = pcc_get_rate(sk);
		mon->valid = 1;
	}
}

/** check if something sent and if anny monitors ended */
static inline void do_checks(struct sock *sk)
{
	struct pcctcp *ca = inet_csk_ca(sk);

	init_pcc_struct(sk, ca);

	check_if_sent(sk);
	check_end_of_monitor_interval(sk);
	
}

/** change the last known sequence to all intervals and the bytes lost for relevant ones */
static void update_interval_with_received_acks(struct sock *sk) 
{
	struct pcctcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int i,j;
	struct tcp_sack_block sack_cache[4];

	init_pcc_struct(sk, ca);

	//sort received sacks according to sequence in increasing order
	if (tp->sacked_out) {
		memcpy(sack_cache, tp->recv_sack_cache, sizeof(sack_cache));
		for (i = 0; i < 4; i++) {
			for (j = i+1; j < 4; j++) {
				if (after(sack_cache[i].start_seq, sack_cache[j].start_seq)) {
					u32 tmp = sack_cache[i].start_seq;
					sack_cache[i].start_seq = sack_cache[j].start_seq;
					sack_cache[j].start_seq = tmp;

					tmp = sack_cache[i].end_seq;
					sack_cache[i].end_seq = sack_cache[j].end_seq;
					sack_cache[j].end_seq = tmp;
				}
			}
		}
	}
	
	//for all active intervals check if cumulative acks changed the last known seq, or if the sacks did
	for (i = 0; i < NUMBER_OF_INTERVALS; i++) {
		struct monitor *loop_mon = ca->pcc->monitor_intervals + i;
		if (!loop_mon->valid) {
			continue;
		}

		//set the last known sequence to the last cumulative ack if it is better than the last known seq
		if (after(tp->snd_una, loop_mon->last_acked_seq)) {
			loop_mon->last_acked_seq = tp->snd_una;
		}

		//there are sacks
		if (tp->sacked_out) {
			for (j = 0; j < 4; j++) {
				//if the sack doesn't bring any new information, check the next one
				if (!before(loop_mon->last_acked_seq, loop_mon->snd_end_seq)) {
					continue;
				}

				//mark the hole as lost bytes in this monitor interval
				if (sack_cache[j].start_seq != 0 && sack_cache[j].end_seq != 0) {
					if (before(loop_mon->last_acked_seq, sack_cache[j].start_seq)) {
						if (before(sack_cache[j].start_seq, loop_mon->snd_end_seq)) {
							s32 lost = sack_cache[j].start_seq - loop_mon->last_acked_seq;
							loop_mon->bytes_lost += lost;
							DBG_PRINT("monitor %d lost from start sack (%u-%u) to last acked (%u), lost :%d\n", i, sack_cache[j].start_seq, sack_cache[j].end_seq, loop_mon->last_acked_seq, lost);
						} else {
							s32 lost = loop_mon->snd_end_seq - loop_mon->last_acked_seq;
							loop_mon->bytes_lost += lost;
							DBG_PRINT("monitor %d lost from last acked (%u) to end of monitor (%u), lost: %d\n", i, loop_mon->last_acked_seq, loop_mon->snd_end_seq, lost);
						}

					}
					//update the last known seq if it was changed
					if (after(sack_cache[j].end_seq, loop_mon->last_acked_seq)) {
						loop_mon->last_acked_seq = sack_cache[j].end_seq;
					}
				}
			}
		}
	}

}


static void pcctcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct pcctcp *ca = inet_csk_ca(sk);

	
	sk->sk_pacing_rate = INITIAL_RATE;
}

static u32 ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	do_checks(sk);
	return TCP_INFINITE_SSTHRESH;
}

static void pkts_acked(struct sock *sk, const struct ack_sample * sample)
{
	int i;
	struct tcp_sock *tp = tcp_sk(sk);
	struct pcctcp *ca = inet_csk_ca(sk);

	init_pcc_struct(sk, ca);

	if (sample->rtt_us > 0) {
		ca->pcc->last_rtt = (sample->rtt_us);
	}

	update_interval_with_received_acks(sk);
	do_checks(sk);

	//set the congestion window to a very large size so it wouldn't matter
	tp->snd_cwnd = LARGE_CWND;
	//tp->rcv_wnd = LARGE_CWND;
	tp->snd_wnd = 0xffffff;
	//tp->snd_cwnd_clamp = LARGE_CWND;
}

static void in_ack_event(struct sock *sk, u32 flags)
{
	update_interval_with_received_acks(sk);
}

static void cong_control(struct sock *sk, const struct rate_sample *rs)
{
	//struct pcctcp *ca = inet_csk_ca(sk);
	//struct monitor * mon = ca->pcc->monitor_intervals + ca->pcc->current_interval;
	//	update_interval_with_received_acks(sk);

	return;
}

static void pcc_release(struct sock *sk)
{
	struct pcctcp *ca = inet_csk_ca(sk);

	DBG_PRINT(KERN_INFO "[PCC] in release routine\n");
	
	if (ca->pcc != NULL) {
		kfree(ca->pcc);
	}
	ca->pcc = NULL;
}

static struct tcp_congestion_ops pcctcp_ops __read_mostly = {
	.init		= pcctcp_init,
	.ssthresh	= ssthresh,
	.pkts_acked     = pkts_acked,
	.release 	= pcc_release,
	.cong_control	= cong_control,
	.owner		= THIS_MODULE,
	.name		= "pcc",
	.in_ack_event = in_ack_event,
};



static int __init pcctcp_ops_register(void)
{
	BUILD_BUG_ON(sizeof(struct pcctcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&pcctcp_ops);
}

static void __exit pcctcp_ops_unregister(void)
{
	tcp_unregister_congestion_control(&pcctcp_ops);
}

module_init(pcctcp_ops_register);
module_exit(pcctcp_ops_unregister);


MODULE_AUTHOR("Tomer Gilad");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("PCC TCP");
MODULE_VERSION("1.0");
