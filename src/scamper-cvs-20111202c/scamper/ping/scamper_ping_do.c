/*
 * scamper_do_ping.c
 *
 * $Id: scamper_ping_do.c,v 1.125 2011/10/25 01:10:12 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * 
 */

#ifndef lint
static const char rcsid[] =
  "$Id: scamper_ping_do.c,v 1.125 2011/10/25 01:10:12 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_getsrc.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_probe.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_ping_do.h"
#include "scamper_options.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "utils.h"

#define SCAMPER_DO_PING_PROBECOUNT_MIN    1
#define SCAMPER_DO_PING_PROBECOUNT_DEF    4
#define SCAMPER_DO_PING_PROBECOUNT_MAX    65535

#define SCAMPER_DO_PING_PROBEWAIT_MIN     1
#define SCAMPER_DO_PING_PROBEWAIT_DEF     1
#define SCAMPER_DO_PING_PROBEWAIT_MAX     20

#define SCAMPER_DO_PING_PROBETTL_MIN      1
#define SCAMPER_DO_PING_PROBETTL_DEF      64
#define SCAMPER_DO_PING_PROBETTL_MAX      255

#define SCAMPER_DO_PING_PROBETOS_MIN      0
#define SCAMPER_DO_PING_PROBETOS_DEF      0
#define SCAMPER_DO_PING_PROBETOS_MAX      255

#define SCAMPER_DO_PING_PROBEMETHOD_MIN   0
#define SCAMPER_DO_PING_PROBEMETHOD_DEF   0
#define SCAMPER_DO_PING_PROBEMETHOD_MAX   4

#define SCAMPER_DO_PING_PROBEDPORT_MIN    0
#define SCAMPER_DO_PING_PROBEDPORT_MAX    65535

#define SCAMPER_DO_PING_PROBESPORT_MIN    0
#define SCAMPER_DO_PING_PROBESPORT_MAX    65535

#define SCAMPER_DO_PING_REPLYCOUNT_MIN    0
#define SCAMPER_DO_PING_REPLYCOUNT_DEF    0
#define SCAMPER_DO_PING_REPLYCOUNT_MAX    65535

#define SCAMPER_DO_PING_PATTERN_MIN       1
#define SCAMPER_DO_PING_PATTERN_DEF       0
#define SCAMPER_DO_PING_PATTERN_MAX       32

/* the callback functions registered with the ping task */
static scamper_task_funcs_t ping_funcs;

/* ICMP ping probes are marked with the process' ID */
#ifndef _WIN32
static pid_t pid;
#else
static DWORD pid;
#endif

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

typedef struct ping_probe
{
  struct timeval     tx;
  uint16_t           ipid;
} ping_probe_t;

typedef struct ping_state
{
  ping_probe_t     **probes;
  uint16_t           replies;
  uint16_t           seq;
  uint8_t           *payload;
  uint16_t           payload_len;
  uint8_t           *tsps;
  uint8_t            tsps_len;
  uint32_t           tcp_seq;
  uint32_t           tcp_ack;
} ping_state_t;

#define PING_OPT_PAYLOAD      1
#define PING_OPT_PROBECOUNT   2
#define PING_OPT_PROBEICMPSUM 3
#define PING_OPT_PROBESPORT   4
#define PING_OPT_PROBEDPORT   5
#define PING_OPT_PROBEWAIT    6
#define PING_OPT_PROBETTL     7
#define PING_OPT_REPLYCOUNT   8
#define PING_OPT_OPTION       9
#define PING_OPT_PATTERN      10
#define PING_OPT_PROBEMETHOD  11
#define PING_OPT_RECORDROUTE  12
#define PING_OPT_USERID       13
#define PING_OPT_PROBESIZE    14
#define PING_OPT_SRCADDR      15
#define PING_OPT_TIMESTAMP    16
#define PING_OPT_PROBETOS     17

static const scamper_option_in_t opts[] = {
  {'B', NULL, PING_OPT_PAYLOAD,      SCAMPER_OPTION_TYPE_STR},
  {'c', NULL, PING_OPT_PROBECOUNT,   SCAMPER_OPTION_TYPE_NUM},
  {'C', NULL, PING_OPT_PROBEICMPSUM, SCAMPER_OPTION_TYPE_STR},
  {'d', NULL, PING_OPT_PROBEDPORT,   SCAMPER_OPTION_TYPE_NUM},
  {'F', NULL, PING_OPT_PROBESPORT,   SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, PING_OPT_PROBEWAIT,    SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, PING_OPT_PROBETTL,     SCAMPER_OPTION_TYPE_NUM},
  {'o', NULL, PING_OPT_REPLYCOUNT,   SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, PING_OPT_OPTION,       SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, PING_OPT_PATTERN,      SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, PING_OPT_PROBEMETHOD,  SCAMPER_OPTION_TYPE_STR},
  {'R', NULL, PING_OPT_RECORDROUTE,  SCAMPER_OPTION_TYPE_NULL},
  {'U', NULL, PING_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, PING_OPT_PROBESIZE,    SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, PING_OPT_SRCADDR,      SCAMPER_OPTION_TYPE_STR},
  {'T', NULL, PING_OPT_TIMESTAMP,    SCAMPER_OPTION_TYPE_STR},
  {'z', NULL, PING_OPT_PROBETOS,     SCAMPER_OPTION_TYPE_NUM},
};

static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_ping_usage(void)
{
  return "ping [-R] [-B payload] [-c count] [-C icmp-sum] [-d dport]\n"
         "     [-F sport] [-i wait-probe] [-m ttl] [-o reply-count]\n"
         "     [-O option] [-p pattern] [-P method] [-U userid]\n"
         "     [-s probe-size] [-S srcaddr] [-T timestamp-option] [-z tos]";
}

static scamper_ping_t *ping_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static ping_state_t *ping_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void ping_stop(scamper_task_t *task, uint8_t reason, uint8_t data)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping->stop_reason = reason;
  ping->stop_data   = data;
  scamper_task_queue_done(task, 0);
  return;  
}

static void ping_handleerror(scamper_task_t *task, int error)
{
  ping_stop(task, SCAMPER_PING_STOP_ERROR, error);
  return;
}

static uint16_t match_ipid(scamper_task_t *task, uint16_t ipid)
{
  scamper_ping_t *ping  = ping_getdata(task);
  ping_state_t   *state = ping_getstate(task);
  uint16_t        seq;

  assert(state->seq > 0);

  for(seq = state->seq-1; state->probes[seq]->ipid != ipid; seq--)
    {
      if(seq == 0 || ping->ping_sent - 5 == seq)
	{
	  seq = state->seq - 1;
	  break;
	}
    }

  return seq;
}

static void do_ping_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  scamper_ping_t       *ping  = ping_getdata(task);
  ping_state_t         *state = ping_getstate(task);
  scamper_ping_reply_t *reply = NULL;
  ping_probe_t         *probe;
  int                   seq;

  if(state->seq == 0)
    return;

  if(SCAMPER_DL_IS_TCP(dl) == 0)
    return;

  if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
    {
      /*
       * we send a series of probes using the same src/dst ports.  the
       * responses should match accordingly.
       */
      if(dl->dl_tcp_dport != ping->probe_sport ||
	 dl->dl_tcp_sport != ping->probe_dport)
	return;

      /*
       * for TCP targets that might echo the IPID, use that to match probes.
       * note that there exists the possibility that replies might be associated
       * with the wrong probe by random chance.
       */
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	seq = match_ipid(task, dl->dl_ip_id);
      else
	seq = state->seq - 1;
    }
  else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT)
    {
      /* the response should be from the destination port probed */
      if(dl->dl_tcp_sport != ping->probe_dport)
	return;

      seq = dl->dl_tcp_dport;
      if(dl->dl_tcp_dport < ping->probe_sport)
	seq = seq + 0x10000;
      seq = seq - ping->probe_sport;
      if(seq >= state->seq)
	return;
    }
  else
    {
      return;
    }

  /* this is probably the probe which goes with the reply */
  probe = state->probes[seq];
  assert(probe != NULL);

  scamper_dl_rec_tcp_print(dl);

  /* allocate a reply structure for the response */
  if((reply = scamper_ping_reply_alloc()) == NULL)
    {
      goto err;
    }

  /* figure out where the response came from */
  if((reply->addr = scamper_addrcache_get(addrcache, ping->dst->type,
					  dl->dl_ip_src)) == NULL)
    {
      goto err;
    }

  /* put together details of the reply */
  timeval_diff_tv(&reply->rtt, &probe->tx, &dl->dl_tv);
  reply->reply_size  = dl->dl_ip_size;
  reply->reply_proto = dl->dl_ip_proto;
  reply->probe_id    = seq;
  reply->tcp_flags   = dl->dl_tcp_flags;

  if(dl->dl_af == AF_INET)
    {
      reply->reply_ipid = dl->dl_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;

      reply->probe_ipid = probe->ipid;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;
    }

  reply->reply_ttl = dl->dl_ip_ttl;
  reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;

  /*
   * if this is the first reply we have for this hop, then increment
   * the replies counter we keep state with
   */
  if(ping->ping_replies[seq] == NULL)
    {
      state->replies++;
    }

  /* put the reply into the ping table */
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  if(ping->reply_count != 0 && state->replies >= ping->reply_count)
    {
      ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
    }

  return;

 err:
  ping_handleerror(task, errno);
  return;
}

static void do_ping_handle_icmp(scamper_task_t *task, scamper_icmp_resp_t *ir)
{
  scamper_ping_t            *ping  = ping_getdata(task);
  ping_state_t              *state = ping_getstate(task);
  scamper_ping_reply_t      *reply = NULL;
  ping_probe_t              *probe;
  int                        seq;
  scamper_addr_t             addr;
  uint8_t                    i, rrc = 0, tsc = 0;
  struct in_addr            *rrs = NULL, *tsips = NULL;
  uint32_t                  *tstss = NULL;
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;

  /* if we haven't sent a probe yet */
  if(state->seq == 0)
    return;

  scamper_icmp_resp_print(ir);

  /* if this is an echo reply packet, then check the id and sequence */
  if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir))
    {
      /* if the response is not for us, then move on */
      if(SCAMPER_PING_METHOD_IS_ICMP(ping) == 0)
	return;
      if(ir->ir_icmp_id != ping->probe_sport)
	return;

      seq = ir->ir_icmp_seq;
      if(seq < ping->probe_dport)
	seq = seq + 0x10000;
      seq = seq - ping->probe_dport;

      if(seq >= state->seq)
	return;

      if(ir->ir_af == AF_INET)
	{
	  if(ir->ir_ipopt_rrc > 0)
	    {
	      rrc = ir->ir_ipopt_rrc;
	      rrs = ir->ir_ipopt_rrs;
	    }
	  if(ir->ir_ipopt_tsc > 0)
	    {
	      tsc   = ir->ir_ipopt_tsc;
	      tstss = ir->ir_ipopt_tstss;
	      tsips = ir->ir_ipopt_tsips;
	    }	     
	}
    }
  else if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir))
    {
      if(SCAMPER_ICMP_RESP_IS_UNREACH(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) == 0)
	{
	  return;
	}

      if(ir->ir_inner_ip_off != 0)
	return;

      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_ICMP_ECHO_REQ(ir) == 0 ||
	     ir->ir_inner_icmp_id != ping->probe_sport)
	    {
	      return;
	    }

	  seq = ir->ir_inner_icmp_seq;
	  if(seq < ping->probe_dport)
	    seq = seq + 0x10000;
	  seq = seq - ping->probe_dport;

	  if(seq >= state->seq)
	    return;
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_TCP(ir) == 0 ||
	     ir->ir_inner_tcp_dport != ping->probe_dport)
	    {
	      return;
	    }

	  if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
	    {
	      if(ir->ir_inner_tcp_sport != ping->probe_sport)
		return;

	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else
	    {
	      if(ir->ir_inner_tcp_sport > ping->probe_sport + state->seq ||
		 ir->ir_inner_tcp_sport < ping->probe_sport)
		return;

	      seq = ir->ir_inner_tcp_sport - ping->probe_sport;
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_UDP(ir) == 0 ||
	     ir->ir_inner_udp_sport != ping->probe_sport)
	    {
	      return;
	    }

	  if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	    {
	      if(ir->ir_inner_udp_dport != ping->probe_dport)
		return;

	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_UDP_DPORT)
	    {
	      if(ir->ir_inner_udp_dport > ping->probe_dport + state->seq ||
		 ir->ir_inner_udp_dport < ping->probe_dport)
		return;

	      seq = ir->ir_inner_udp_dport - ping->probe_dport;
	    }
	  else
	    {
	      return;
	    }
	}
      else
	{
	  return;
	}

      if(ir->ir_af == AF_INET)
	{
	  if(ir->ir_inner_ipopt_rrc > 0)
	    {
	      rrc = ir->ir_inner_ipopt_rrc;
	      rrs = ir->ir_inner_ipopt_rrs;
	    }
	  if(ir->ir_inner_ipopt_tsc > 0)
	    {
	      tsc   = ir->ir_inner_ipopt_tsc;
	      tstss = ir->ir_inner_ipopt_tstss;
	      tsips = ir->ir_inner_ipopt_tsips;
	    }
	}
    }
  else return;

  probe = state->probes[seq];
  assert(probe != NULL);

  /* allocate a reply structure for the response */
  if((reply = scamper_ping_reply_alloc()) == NULL)
    {
      goto err;
    }

  /* figure out where the response came from */
  if(scamper_icmp_resp_src(ir, &addr) != 0)
    goto err;
  reply->addr = scamper_addrcache_get(addrcache, addr.type, addr.addr);
  if(reply->addr == NULL)
    goto err;

  /* put together details of the reply */
  timeval_diff_tv(&reply->rtt, &probe->tx, &ir->ir_rx);
  reply->reply_size  = ir->ir_ip_size;
  reply->probe_id    = seq;
  reply->icmp_type   = ir->ir_icmp_type;
  reply->icmp_code   = ir->ir_icmp_code;

  if(ir->ir_af == AF_INET)
    {
      reply->reply_ipid = ir->ir_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;

      reply->probe_ipid = probe->ipid;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;

      reply->reply_proto = IPPROTO_ICMP;

      if(rrs != NULL && rrc > 0)
	{
	  if((v4rr = scamper_ping_reply_v4rr_alloc(rrc)) == NULL)
	    goto err;
	  reply->v4rr = v4rr;

	  for(i=0; i<rrc; i++)
	    {
	      v4rr->rr[i] = scamper_addrcache_get_ipv4(addrcache, &rrs[i]);
	      if(v4rr->rr[i] == NULL)
		goto err;
	    }
	}

      if(tsc > 0 && tstss != NULL)
	{
	  if(tsips != NULL)
	    v4ts = scamper_ping_reply_v4ts_alloc(tsc, 1);
	  else
	    v4ts = scamper_ping_reply_v4ts_alloc(tsc, 0);

	  if(v4ts == NULL)
	    goto err;
	  reply->v4ts = v4ts;

	  v4ts->tsc = tsc;
	  for(i=0; i<tsc; i++)
	    {
	      if(tsips != NULL)
		{
		  v4ts->ips[i]=scamper_addrcache_get_ipv4(addrcache,&tsips[i]);
		  if(v4ts->ips[i] == NULL)
		    goto err;
		}

	      v4ts->tss[i] = tstss[i];
	    }
	}
    }
  else if(ir->ir_af == AF_INET6)
    {
      reply->reply_proto = IPPROTO_ICMPV6;
    }

  if(ir->ir_ip_ttl != -1)
    {
      reply->reply_ttl = (uint8_t)ir->ir_ip_ttl;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;
    }

  /*
   * if this is the first reply we have for this hop, then increment
   * the replies counter we keep state with
   */
  if(ping->ping_replies[seq] == NULL)
    state->replies++;

  /* put the reply into the ping table */
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  if(ping->reply_count != 0 && state->replies >= ping->reply_count)
    ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);

  return;

 err:
  if(reply != NULL) scamper_ping_reply_free(reply);
  ping_handleerror(task, errno);
  return;
}

/*
 * do_ping_handle_timeout
 *
 * the ping object expired on the pending queue
 * that means it is either time to send the next probe, or write the
 * task out
 */
static void do_ping_handle_timeout(scamper_task_t *task)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping_state_t *state = ping_getstate(task);

  if(state->seq == ping->probe_count)
    ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);

  return;
}

static int ping_state_payload(scamper_ping_t *ping, ping_state_t *state)
{
  scamper_addr_t *src;
  int i = 0;
  int al;
  int hdr;

  /* payload to send in the probe */
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      al = 4;
      hdr = 20;
      if((ping->flags & SCAMPER_PING_FLAG_V4RR) != 0)
	hdr += 40;
      else if((ping->flags & SCAMPER_PING_FLAG_TSONLY) != 0)
	hdr += 40;
      else if((ping->flags & SCAMPER_PING_FLAG_TSANDADDR) != 0)
	hdr += 36;
      else if(state->tsps != NULL)
	hdr += (state->tsps_len * 2) + 4;
    }
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      al = 16;
      hdr = 40;
    }
  else
    {
      return -1;
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    state->payload_len = ping->probe_size - hdr - 8;
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    state->payload_len = ping->probe_size - hdr - 20;
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    state->payload_len = ping->probe_size - hdr - 8;
  else
    return -1;

  if(state->payload_len == 0)
    return 0;

  if((state->payload = malloc(state->payload_len)) == NULL)
    return -1;

  if((ping->flags & SCAMPER_PING_FLAG_SPOOF) != 0)
    {
      assert(i == 0);
      assert(state->payload_len >= al);

      /* get the source IP address to embed in the probe */
      if((src = scamper_getsrc(ping->dst, 0)) == NULL)
	return -1;
      memcpy(state->payload, src->addr, al);
      i += al;

      scamper_addr_free(src);
    }

  /* need scratch space in the probe to help fudge icmp checksum */
  if((ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
    {
      assert(state->payload_len >= i + 2);
      state->payload[i++] = 0;
      state->payload[i++] = 0;
    }

  if(ping->probe_data != NULL)
    {
      if((ping->flags & SCAMPER_PING_FLAG_PAYLOAD) != 0)
	{
	  assert(state->payload_len >= i + ping->probe_datalen);
	  memcpy(state->payload+i, ping->probe_data, ping->probe_datalen);
	  i += ping->probe_datalen;
	}
      else
	{
	  while((size_t)(i + ping->probe_datalen) < state->payload_len)
	    {
	      memcpy(state->payload+i, ping->probe_data, ping->probe_datalen);
	      i += ping->probe_datalen;
	    }
	  memcpy(state->payload+i, ping->probe_data, state->payload_len-i);
	  i = state->payload_len;
	}
    }

  if(state->payload_len > i)
    memset(state->payload+i, 0, state->payload_len - i);

  return 0;
}

static void ping_state_free(ping_state_t *state)
{
  int i;

  if(state->probes != NULL)
    {
      for(i=0; i<state->seq; i++)
	if(state->probes[i] != NULL)
	  free(state->probes[i]);
      free(state->probes);
    }

  if(state->payload != NULL)
    free(state->payload);

  if(state->tsps != NULL)
    free(state->tsps);

  free(state);
  return;
}

static int ping_state_alloc(scamper_task_t *task)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping_state_t *state = NULL;
  size_t size;
  int i;

  if(scamper_ping_replies_alloc(ping, ping->probe_count) != 0)
    {
      printerror(errno, strerror, __func__, "could not malloc replies");
      goto err;
    }

  if((state = malloc_zero(sizeof(ping_state_t))) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state");
      goto err;
    }
  scamper_task_setstate(task, state);

  size = ping->probe_count * sizeof(ping_probe_t *);
  if((state->probes = malloc_zero(size)) == NULL)
    {
      printerror(errno, strerror, __func__, "could not malloc state->probes");
      goto err;
    }

  /* sort out the payload to attach with each probe */
  if(ping_state_payload(ping, state) != 0)
    goto err;

  if(ping->probe_tsps != NULL)
    {
      if((state->tsps = malloc(4 * ping->probe_tsps->ipc)) == NULL)
	{
	  printerror(errno,strerror,__func__, "could not malloc state->tsps");
	  goto err;
	}
      for(i=0; i<ping->probe_tsps->ipc; i++)
	memcpy(state->tsps+(i*4), ping->probe_tsps->ips[i]->addr, 4);
      state->tsps_len = ping->probe_tsps->ipc * 4;
    }

  if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
      if(random_u32(&state->tcp_seq) != 0 || random_u32(&state->tcp_ack) != 0)
	return -1;
    }

  return 0;

 err:
  return -1;
}

/*
 * do_ping_probe
 *
 * it is time to send a probe for this task.  figure out the form of the
 * probe to send, and then send it.
 */
static void do_ping_probe(scamper_task_t *task)
{
  scamper_probe_ipopt_t opt;
  scamper_ping_t  *ping  = ping_getdata(task);
  ping_state_t    *state = ping_getstate(task);
  ping_probe_t    *pp = NULL;
  scamper_probe_t  probe;
  int              i;
  uint16_t         ipid = 0;
  uint16_t         u16;

  if(state == NULL)
    {
      if(ping_state_alloc(task) != 0)
	goto err;
      state = ping_getstate(task);

      /* timestamp the start time of the ping */
      gettimeofday_wrap(&ping->start);
    }

  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      /* select a random IPID value that is not zero. try up to three times */
      for(i=0; i<3; i++)
	{
	  if(random_u16(&ipid) != 0)
	    {
	      printerror(errno, strerror, __func__, "could not rand ipid");
	      goto err;
	    }

	  if(ipid != 0)
	    break;
	}

      if(ipid == 0)
	goto err;
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_flags     = SCAMPER_PROBE_FLAG_IPID;
  probe.pr_ip_src    = ping->src;
  probe.pr_ip_dst    = ping->dst;
  probe.pr_ip_tos    = ping->probe_tos;
  probe.pr_ip_ttl    = ping->probe_ttl;
  probe.pr_ip_id     = ipid;
  probe.pr_data      = state->payload;
  probe.pr_len       = state->payload_len;

  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    probe.pr_ip_off  = IP_DF;

  if((ping->flags & SCAMPER_PING_FLAG_SPOOF) != 0)
    probe.pr_flags |= SCAMPER_PROBE_FLAG_SPOOF;

  if((ping->flags & SCAMPER_PING_FLAG_V4RR) != 0)
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4RR;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }
  else if((ping->flags & SCAMPER_PING_FLAG_TSONLY) != 0)
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4TSO;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }
  else if((ping->flags & SCAMPER_PING_FLAG_TSANDADDR) != 0)
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4TSAA;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }
  else if(state->tsps != NULL)
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4TSPS;
      opt.val  = state->tsps;
      opt.len  = state->tsps_len;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	{
	  probe.pr_ip_proto  = IPPROTO_ICMP;
	  probe.pr_icmp_type = ICMP_ECHO;
	}
      else
	{
	  probe.pr_ip_proto  = IPPROTO_ICMPV6;
	  probe.pr_icmp_type = ICMP6_ECHO_REQUEST;
	}
      probe.pr_icmp_id   = ping->probe_sport;
      probe.pr_icmp_seq  = ping->probe_dport + state->seq;

      if((ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
	{
	  probe.pr_icmp_sum = u16 = htons(ping->probe_icmpsum);
	  if((ping->flags & SCAMPER_PING_FLAG_SPOOF) != 0)
	    i = 4;
	  else
	    i = 0;
	  memcpy(state->payload+i, &u16, 2);
	  switch(ping->dst->type)
	    {
	    case SCAMPER_ADDR_TYPE_IPV4:
	      u16 = scamper_icmp4_cksum(&probe);
	      break;

	    case SCAMPER_ADDR_TYPE_IPV6:
	      u16 = scamper_icmp6_cksum(&probe);
	      break;
	    }
	  memcpy(state->payload+i, &u16, 2);
	}
    }
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = ping->probe_dport;
      probe.pr_tcp_flags = TH_ACK;

      if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
	{
	  probe.pr_tcp_sport = ping->probe_sport;
	  probe.pr_tcp_seq   = state->tcp_seq;
	  probe.pr_tcp_ack   = state->tcp_ack;
	}
      else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT)
	{
	  probe.pr_tcp_sport = ping->probe_sport + state->seq;
	  if(random_u32(&probe.pr_tcp_seq) != 0 ||
	     random_u32(&probe.pr_tcp_ack) != 0)
	    goto err;
	}
    }
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = ping->probe_sport;

      if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	probe.pr_udp_dport = ping->probe_dport;
      else if(ping->probe_method == SCAMPER_PING_METHOD_UDP_DPORT)
	probe.pr_udp_dport = ping->probe_dport + state->seq;
    }
  else
    {
      goto err;
    }

  /*
   * allocate a ping probe state record before we try and send the probe
   * as there is no point sending something into the wild that we can't
   * record
   */
  if((pp = malloc(sizeof(ping_probe_t))) == NULL)
    goto err;

  if(scamper_probe_task(&probe, task) != 0)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* fill out the details of the probe sent */
  pp->ipid = ipid;
  timeval_cpy(&pp->tx, &probe.pr_tx);

  /* record the probe in the probes table */
  state->probes[state->seq] = pp;

  /* we've sent this sequence number now, so move to the next one */
  state->seq++;

  /* increment the number of probes sent... */
  ping->ping_sent++;

  /* re-queue the ping task */
  scamper_task_queue_wait(task, ping->probe_wait * 1000);

  return;

 err:
  if(pp != NULL) free(pp);
  ping_handleerror(task, errno);
  return;
}

static void do_ping_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_ping(sf, ping_getdata(task));
  return;
}

static int ping_arg_param_validate(int optid, char *param, long *out)
{
  long tmp = 0;
  int i;

  switch(optid)
    {
    case PING_OPT_PAYLOAD:
      for(i=0; param[i] != '\0'; i++)
	if(ishex(param[i]) == 0)
	  goto err;
      if(i == 0 || (i % 2) != 0)
	goto err;
      tmp = i / 2;
      if(tmp > 1000)
	goto err;
      break;

    case PING_OPT_PROBECOUNT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBECOUNT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBECOUNT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBEICMPSUM:
      if(string_tolong(param, &tmp) == -1 || tmp < 0 || tmp > 65535)
	goto err;
      break;

    case PING_OPT_PROBEDPORT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBEDPORT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBEDPORT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBESPORT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBESPORT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBESPORT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBEMETHOD:
      if(strcasecmp(param, "icmp-echo") == 0)
	tmp = SCAMPER_PING_METHOD_ICMP_ECHO;
      else if(strcasecmp(param, "tcp-ack") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_ACK;
      else if(strcasecmp(param, "tcp-ack-sport") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_ACK_SPORT;
      else if(strcasecmp(param, "udp") == 0)
	tmp = SCAMPER_PING_METHOD_UDP;
      else if(strcasecmp(param, "udp-dport") == 0)
	tmp = SCAMPER_PING_METHOD_UDP_DPORT;
      else
	goto err;
      break;

    /* how long to wait between sending probes */
    case PING_OPT_PROBEWAIT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBEWAIT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBEWAIT_MAX)
	{
	  goto err;
	}
      break;

    /* the ttl to probe with */
    case PING_OPT_PROBETTL:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBETTL_MIN  ||
	 tmp > SCAMPER_DO_PING_PROBETTL_MAX)
	{
	  goto err;
	}
      break;

    /* how many unique replies are required before the ping completes */
    case PING_OPT_REPLYCOUNT:
      if(string_tolong(param, &tmp) == -1  ||
	 tmp < SCAMPER_DO_PING_REPLYCOUNT_MIN ||
	 tmp > SCAMPER_DO_PING_REPLYCOUNT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_OPTION:
      if(strcasecmp(param, "spoof") != 0)
	goto err;
      break;

    case PING_OPT_PATTERN:
      /*
       * sanity check that only hex characters are present, and that
       * the pattern string is not too long.
       */
      for(i=0; i<SCAMPER_DO_PING_PATTERN_MAX; i++)
	{
	  if(param[i] == '\0') break;
	  if(ishex(param[i]) == 0) goto err;
	}
      if(i == SCAMPER_DO_PING_PATTERN_MAX) goto err;
      break;

    /* the size of each probe */
    case PING_OPT_PROBESIZE:
      if(string_tolong(param, &tmp) == -1 || tmp < 0 || tmp > 65535)
	{
	  goto err;
	}
      break;

    case PING_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
      break;

    case PING_OPT_SRCADDR:
    case PING_OPT_TIMESTAMP:
      break;

    /* the tos bits to include in each probe */
    case PING_OPT_PROBETOS:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_PING_PROBETOS_MIN  ||
	 tmp > SCAMPER_DO_PING_PROBETOS_MAX)
	{
	  goto err;
	}
      break;

    default:
      return -1;
    }

  /* valid parameter */
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  return -1;
}

/*
 * scamper_do_ping_arg_validate
 *
 *
 */
int scamper_do_ping_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  ping_arg_param_validate);
}

static int ping_tsopt(scamper_ping_t *ping, uint8_t *flags, char *tsopt)
{
  scamper_ping_v4ts_t *ts = NULL;
  char *ips[4], *ptr = tsopt;
  int i = 0;

  while(*ptr != '=' && *ptr != '\0')
    ptr++;

  if(strncasecmp(tsopt, "tsprespec", 9) == 0 && *ptr == '=')
    {
      ptr++;
      for(;;)
	{
	  if(i == 4)
	    return -1;

	  ips[i++] = ptr;

	  while(isdigit((int)*ptr) || *ptr == '.')
	    ptr++;

	  if(*ptr == '\0')
	    break;
	  if(*ptr != ',')
	    return -1;

	  *ptr = '\0';
	  ptr++;
	}

      if((ts = scamper_ping_v4ts_alloc(i)) == NULL)
	return -1;

      i--;
      while(i>=0)
	{
	  ts->ips[i] = scamper_addrcache_resolve(addrcache, AF_INET, ips[i]);
	  if(ts->ips[i] == NULL)
	    {
	      scamper_ping_v4ts_free(ts);
	      return -1;
	    }
	  i--;
	}

      ping->probe_tsps = ts;
    }
  else if(*ptr == '\0' && strcasecmp(tsopt, "tsonly") == 0)
    {
      *flags |= SCAMPER_PING_FLAG_TSONLY;
    }
  else if(*ptr == '\0' && strcasecmp(tsopt, "tsandaddr") == 0)
    {
      *flags |= SCAMPER_PING_FLAG_TSANDADDR;
    }
  else
    {
      return -1;
    }

  return 0;
}

/*
 * scamper_do_ping_alloc
 *
 * given a string representing a ping task, parse the parameters and assemble
 * a ping.  return the ping structure so that it is all ready to go.
 *
 */
void *scamper_do_ping_alloc(char *str)
{
  uint16_t  probe_count   = SCAMPER_DO_PING_PROBECOUNT_DEF;
  uint8_t   probe_wait    = SCAMPER_DO_PING_PROBEWAIT_DEF;
  uint8_t   probe_ttl     = SCAMPER_DO_PING_PROBETTL_DEF;
  uint8_t   probe_tos     = SCAMPER_DO_PING_PROBETOS_DEF;
  uint8_t   probe_method  = SCAMPER_DO_PING_PROBEMETHOD_DEF;
  int       probe_sport   = -1;
  int       probe_dport   = -1;
  uint16_t  reply_count   = SCAMPER_DO_PING_REPLYCOUNT_DEF;
  uint16_t  probe_size    = 0; /* unset */
  uint16_t  pattern_len   = 0;
  uint16_t  probe_icmpsum = 0;
  uint8_t   pattern[SCAMPER_DO_PING_PATTERN_MAX/2];
  uint16_t  payload_len   = 0;
  uint8_t  *payload       = NULL;
  uint32_t  userid        = 0;
  uint8_t   flags         = 0;
  char     *src           = NULL;
  char     *tsopt         = NULL;
  int       af;

  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_ping_t *ping = NULL;
  uint16_t cmps = 0; /* calculated minimum probe size */
  char *addr;
  size_t size;
  long tmp = 0;
  int i;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      goto err;
    }

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 ping_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case PING_OPT_PAYLOAD:
	  payload_len = (uint16_t)tmp;
	  if(payload_len == 0 || (payload = malloc(payload_len)) == NULL)
	    goto err;
	  for(i=0; i<payload_len; i++)
	    payload[i] = hex2byte(opt->str[i*2], opt->str[(i*2)+1]);
	  flags |= SCAMPER_PING_FLAG_PAYLOAD;
	  break;

	case PING_OPT_PROBECOUNT:
	  probe_count = (uint16_t)tmp;
	  break;

	case PING_OPT_PROBEDPORT:
	  probe_dport = (uint16_t)tmp;
	  break;

	case PING_OPT_PROBESPORT:
	  probe_sport = (int)tmp;
	  break;

	case PING_OPT_PROBEMETHOD:
	  probe_method = (uint8_t)tmp;
	  break;

	/* how long to wait between sending probes */
	case PING_OPT_PROBEWAIT:
	  probe_wait = (uint8_t)tmp;
	  break;

	/* the ttl to probe with */
	case PING_OPT_PROBETTL:
	  probe_ttl = (uint8_t)tmp;
	  break;

	case PING_OPT_PROBEICMPSUM:
	  probe_icmpsum = (uint16_t)tmp;
	  flags |= SCAMPER_PING_FLAG_ICMPSUM;
	  break;

	/* how many unique replies are required before the ping completes */
	case PING_OPT_REPLYCOUNT:
	  reply_count = (uint16_t)tmp;
	  break;

	case PING_OPT_OPTION:
	  if(strcasecmp(opt->str, "spoof") == 0)
	    flags |= SCAMPER_PING_FLAG_SPOOF;
	  else
	    {
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	/* the pattern to fill each probe with */
	case PING_OPT_PATTERN:
	  size = strlen(opt->str);
	  if((size % 2) == 0)
	    {
	      pattern_len = size/2;
	      for(i=0; i<pattern_len; i++)
		pattern[i] = hex2byte(opt->str[i*2], opt->str[(i*2)+1]);
	    }
	  else
	    {
	      pattern_len = (size/2) + 1;
	      pattern[0] = hex2byte('0', opt->str[0]);
	      for(i=1; i<pattern_len; i++)
		pattern[i] = hex2byte(opt->str[(i*2)-1], opt->str[i*2]);
	    }
	  break;

	/* the size of each probe */
	case PING_OPT_PROBESIZE:
	  probe_size = (uint16_t)tmp;
	  break;

	case PING_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case PING_OPT_RECORDROUTE:
	  flags |= SCAMPER_PING_FLAG_V4RR;
	  break;

	case PING_OPT_SRCADDR:
	  if(src != NULL)
	    goto err;
	  src = opt->str;
	  break;

	case PING_OPT_TIMESTAMP:
	  if(tsopt != NULL)
	    goto err;
	  tsopt = opt->str;
	  break;

	/* the tos bits to include in each probe */
	case PING_OPT_PROBETOS:
	  probe_tos = (uint8_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  /* allocate the ping object and determine the address to probe */
  if((ping = scamper_ping_alloc()) == NULL)
    {
      goto err;
    }
  if((ping->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      goto err;
    }
  ping->probe_method = probe_method;

  /* only one of these two should be specified */
  if(pattern_len != 0 && payload_len != 0)
    goto err;

  /*
   * put together the timestamp option now so we can judge how large the
   * options will be
   */
  if(tsopt != NULL)
    {
      if(ping->dst->type != SCAMPER_ADDR_TYPE_IPV4)
	goto err;

      if((flags & SCAMPER_PING_FLAG_V4RR) != 0)
	goto err;

      if(ping_tsopt(ping, &flags, tsopt) != 0)
	goto err;
    }

  /* ensure the probe size specified is suitable */
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      cmps = 20;

      if(flags & SCAMPER_PING_FLAG_V4RR)
	cmps += 40;
      else if(ping->probe_tsps != NULL)
	cmps += (8 * ping->probe_tsps->ipc) + 4;
      else if(flags & SCAMPER_PING_FLAG_TSONLY)
	cmps += 40;
      else if(flags & SCAMPER_PING_FLAG_TSANDADDR)
	cmps += 36;

      /* record an IP address in the payload */
      if(flags & SCAMPER_PING_FLAG_SPOOF)
	cmps += 4;
    }
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      cmps = 40;
      if(flags & SCAMPER_PING_FLAG_SPOOF)
	cmps += 16;
    }
  else goto err;

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      cmps += 8;

      if(flags & SCAMPER_PING_FLAG_ICMPSUM)
	cmps += 2;

      if(payload_len != 0)
	cmps += payload_len;

      if(probe_size == 0)
	{
	  probe_size = cmps;
	  if(payload_len == 0)
	    probe_size += 56;
	}
    }
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
      cmps += 20;

      if(payload_len != 0)
	cmps += payload_len;

      if(probe_size == 0)
	probe_size = cmps;
    }
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      cmps += 8;

      if(payload_len != 0)
	cmps += payload_len;

      if(probe_size == 0)
	{
	  probe_size = cmps;
	  if(payload_len == 0)
	    probe_size += 12;
	}
    }
  else goto err;

  if(probe_size < cmps)
    goto err;

  if((flags & SCAMPER_PING_FLAG_ICMPSUM) &&
     SCAMPER_PING_METHOD_IS_ICMP(ping) == 0)
    {
      goto err;
    }

  if(src != NULL)
    {
      af = scamper_addr_af(ping->dst);
      if(af != AF_INET && af != AF_INET6)
	goto err;

      if((ping->src = scamper_addrcache_resolve(addrcache, af, src)) == NULL)
	goto err;
    }

  /* copy in the data bytes, if any */
  if(pattern_len != 0)
    {
      if(scamper_ping_setdata(ping, pattern, pattern_len) != 0)
	goto err;
    }
  else if(payload_len != 0)
    {
      if(scamper_ping_setdata(ping, payload, payload_len) != 0)
	goto err;
    }

  if(probe_sport == -1)
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	probe_sport = pid & 0xffff;
      else
	probe_sport = (pid & 0xffff) | 0x8000;
    }

  if(probe_dport == -1)
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	probe_dport = 0;
      else
	probe_dport = 33435;
    }

  ping->probe_count   = probe_count;
  ping->probe_size    = probe_size;
  ping->probe_wait    = probe_wait;
  ping->probe_ttl     = probe_ttl;
  ping->probe_tos     = probe_tos;
  ping->probe_sport   = probe_sport;
  ping->probe_dport   = probe_dport;
  ping->probe_icmpsum = probe_icmpsum;
  ping->reply_count   = reply_count;
  ping->userid        = userid;
  ping->flags         = flags;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  if(payload != NULL) free(payload);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

static void do_ping_halt(scamper_task_t *task)
{
  ping_stop(task, SCAMPER_PING_STOP_HALTED, 0);
  return;
}

static void do_ping_free(scamper_task_t *task)
{
  scamper_ping_t *ping;
  ping_state_t *state;

  if((ping = ping_getdata(task)) != NULL)
    scamper_ping_free(ping);

  if((state = ping_getstate(task)) != NULL)
    ping_state_free(state);

  return;
}

scamper_task_t *scamper_do_ping_alloctask(void *data, scamper_list_t *list,
					  scamper_cycle_t *cycle)
{
  scamper_ping_t *ping = (scamper_ping_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the ping with it */
  if((task = scamper_task_alloc(ping, &ping_funcs)) == NULL)
    goto err;

  /* declare the signature of the task */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(ping->dst);
  if(ping->src == NULL && (ping->src = scamper_getsrc(ping->dst, 0)) == NULL)
    goto err;
  if((ping->flags & SCAMPER_PING_FLAG_SPOOF) == 0)
    sig->sig_tx_ip_src = scamper_addr_use(ping->src);
  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the ping */
  ping->list  = scamper_list_use(list);
  ping->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void scamper_do_ping_free(void *data)
{
  scamper_ping_free((scamper_ping_t *)data);
  return;
}

void scamper_do_ping_cleanup()
{
  return;
}

int scamper_do_ping_init()
{
  ping_funcs.probe          = do_ping_probe;
  ping_funcs.handle_icmp    = do_ping_handle_icmp;
  ping_funcs.handle_timeout = do_ping_handle_timeout;
  ping_funcs.handle_dl      = do_ping_handle_dl;
  ping_funcs.write          = do_ping_write;
  ping_funcs.task_free      = do_ping_free;
  ping_funcs.halt           = do_ping_halt;

#ifndef _WIN32
  pid = getpid();
#else
  pid = GetCurrentProcessId();
#endif

  return 0;
}