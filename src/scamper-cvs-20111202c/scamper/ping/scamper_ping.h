/*
 * scamper_ping.h
 *
 * $Id: scamper_ping.h,v 1.35 2011/09/16 03:15:44 mjl Exp $
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

#ifndef __SCAMPER_PING_H
#define __SCAMPER_PING_H

#define SCAMPER_PING_REPLY_IS_ICMP(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 && \
  (reply)->reply_proto == 1) ||                    \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 && \
  (reply)->reply_proto == 58))

#define SCAMPER_PING_REPLY_IS_TCP(reply) ( \
 ((reply)->reply_proto == 6))

#define SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) (     \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 0) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 129))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 3) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 1))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply) (   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->reply_proto == 1 &&                             \
  (reply)->icmp_type == 3 && (reply)->icmp_code == 3) ||   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->reply_proto == 58 &&                            \
  (reply)->icmp_type == 1 && (reply)->icmp_code == 4))

#define SCAMPER_PING_REPLY_IS_ICMP_TTL_EXP(reply) (         \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&          \
  (reply)->reply_proto == 1 && (reply)->icmp_type == 11) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&          \
  (reply)->reply_proto == 58 && (reply)->icmp_type == 3))

#define SCAMPER_PING_METHOD_IS_ICMP(ping) (\
 ((ping)->probe_method == SCAMPER_PING_METHOD_ICMP_ECHO))

#define SCAMPER_PING_METHOD_IS_TCP(ping) (                    \
 ((ping)->probe_method == SCAMPER_PING_METHOD_TCP_ACK ||      \
  (ping)->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT))

#define SCAMPER_PING_METHOD_IS_UDP(ping) (                \
 ((ping)->probe_method == SCAMPER_PING_METHOD_UDP ||      \
  (ping)->probe_method == SCAMPER_PING_METHOD_UDP_DPORT))

#define SCAMPER_PING_REPLY_FROM_TARGET(ping, reply) ( \
 (SCAMPER_PING_METHOD_IS_ICMP(ping) &&                \
  SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply)) ||    \
 (SCAMPER_PING_METHOD_IS_TCP(ping) &&                 \
  SCAMPER_PING_REPLY_IS_TCP(reply)) ||                \
 (SCAMPER_PING_METHOD_IS_UDP(ping) &&                 \
  SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply)))

#define SCAMPER_PING_STOP_NONE      0x00 /* null reason */
#define SCAMPER_PING_STOP_COMPLETED 0x01 /* sent all probes */
#define SCAMPER_PING_STOP_ERROR     0x02 /* error occured during ping */
#define SCAMPER_PING_STOP_HALTED    0x03 /* halted */

#define SCAMPER_PING_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_PING_REPLY_FLAG_REPLY_IPID 0x02 /* reply ipid included */
#define SCAMPER_PING_REPLY_FLAG_PROBE_IPID 0x04 /* probe ipid included */

#define SCAMPER_PING_METHOD_ICMP_ECHO     0x00
#define SCAMPER_PING_METHOD_TCP_ACK       0x01
#define SCAMPER_PING_METHOD_TCP_ACK_SPORT 0x02
#define SCAMPER_PING_METHOD_UDP           0x03
#define SCAMPER_PING_METHOD_UDP_DPORT     0x04

#define SCAMPER_PING_FLAG_V4RR            0x01 /* -R: IPv4 record route */
#define SCAMPER_PING_FLAG_SPOOF           0x02 /* -O spoof: spoof src */
#define SCAMPER_PING_FLAG_PAYLOAD         0x04 /* probe_data is payload */
#define SCAMPER_PING_FLAG_TSONLY          0x08 /* -T tsonly */
#define SCAMPER_PING_FLAG_TSANDADDR       0x10 /* -T tsandaddr */
#define SCAMPER_PING_FLAG_ICMPSUM         0x20 /* -C csum */

typedef struct scamper_ping_reply_v4rr
{
  scamper_addr_t **rr;
  uint8_t          rrc;
} scamper_ping_reply_v4rr_t;

typedef struct scamper_ping_reply_v4ts
{
  scamper_addr_t **ips;
  uint32_t        *tss;
  uint8_t          tsc;
} scamper_ping_reply_v4ts_t;

typedef struct scamper_ping_v4ts
{
  scamper_addr_t **ips;
  uint8_t          ipc;
} scamper_ping_v4ts_t;

/*
 * scamper_ping_reply
 *
 * a ping reply structure keeps track of how a ping packet was responded to.
 * the default structure has enough fields for interesting pieces out of an
 * echo reply packet.
 *
 * if the icmp type/code is not an ICMP echo reply packet, then the TLVs
 * defined above may be present in the response.
 */
typedef struct scamper_ping_reply
{
  /* where the response came from */
  scamper_addr_t            *addr;

  /* flags defined by SCAMPER_PING_REPLY_FLAG_* */
  uint8_t                    flags;

  /* the TTL / size of the packet that is returned */
  uint8_t                    reply_proto;
  uint8_t                    reply_ttl;
  uint16_t                   reply_size;
  uint16_t                   reply_ipid;
  uint16_t                   probe_ipid;
  uint16_t                   probe_id;

  /* the icmp type / code returned */
  uint8_t                    icmp_type;
  uint8_t                    icmp_code;

  /* the tcp flags returned */
  uint8_t                    tcp_flags;

  /* the time elapsed between sending the probe and getting this response */
  struct timeval             rtt;

  /* data found in IP options, if any */
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;

  /* if a single probe gets more than one response, they get chained */
  struct scamper_ping_reply *next;

} scamper_ping_reply_t;

/*
 * scamper_ping
 *
 * this structure contains details of a ping between a source and a
 * destination.  is specifies the parameters to the ping and the
 * replies themselves.
 */
typedef struct scamper_ping
{
  /* the list / cycle that this ping is in relation to */
  scamper_list_t        *list;
  scamper_cycle_t       *cycle;
  uint32_t               userid;

  /* source and destination addresses of the ping */
  scamper_addr_t        *src;          /* -S option */
  scamper_addr_t        *dst;

  /* when the ping started */
  struct timeval         start;

  /* why the ping finished */
  uint8_t                stop_reason;
  uint8_t                stop_data;

  /* the data to use inside of a probe.  if null then all zeros */
  uint8_t               *probe_data;
  uint16_t               probe_datalen;

  /* ping options */
  uint16_t               probe_count;   /* -c */
  uint16_t               probe_size;    /* -s */
  uint8_t                probe_method;  /* -P */
  uint8_t                probe_wait;    /* -i */
  uint8_t                probe_ttl;     /* -m */
  uint8_t                probe_tos;     /* -z */
  uint16_t               probe_sport;   /* -F */
  uint16_t               probe_dport;   /* -d */
  uint16_t               probe_icmpsum; /* -C */
  uint16_t               reply_count;   /* -o */
  scamper_ping_v4ts_t   *probe_tsps;    /* -T */
  uint8_t                flags;

  /* actual data collected with the ping */
  scamper_ping_reply_t **ping_replies;
  uint16_t               ping_sent;
} scamper_ping_t;

/* basic routines to allocate and free scamper_ping structures */
scamper_ping_t *scamper_ping_alloc(void);
void scamper_ping_free(scamper_ping_t *ping);
scamper_addr_t *scamper_ping_addr(const void *va);
int scamper_ping_setdata(scamper_ping_t *ping, uint8_t *bytes, uint16_t len);

/* utility function for allocating an array for recording replies */
int scamper_ping_replies_alloc(scamper_ping_t *ping, int count);

/* basic routines to allocate and free scamper_ping_reply structures */
scamper_ping_reply_t *scamper_ping_reply_alloc(void);
void scamper_ping_reply_free(scamper_ping_reply_t *reply);
int scamper_ping_reply_append(scamper_ping_t *p, scamper_ping_reply_t *reply);
uint32_t scamper_ping_reply_count(const scamper_ping_t *ping);

scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_alloc(uint8_t rrc);
void scamper_ping_reply_v4rr_free(scamper_ping_reply_v4rr_t *rr);

scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_alloc(uint8_t tsc, int ip);
void scamper_ping_reply_v4ts_free(scamper_ping_reply_v4ts_t *ts);

scamper_ping_v4ts_t *scamper_ping_v4ts_alloc(uint8_t ipc);
void scamper_ping_v4ts_free(scamper_ping_v4ts_t *ts);

/* routine to return basic stats for the measurement */
int scamper_ping_stats(const scamper_ping_t *ping,
		       uint32_t *nreplies, uint32_t *ndups, uint16_t *nloss,
		       struct timeval *min_rtt, struct timeval *max_rtt,
		       struct timeval *avg_rtt, struct timeval *stddev_rtt);

#endif /* __SCAMPER_PING_H */
