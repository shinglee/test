/*
 * scamper_tcp4.c
 *
 * $Id: scamper_tcp4.c,v 1.52 2011/11/17 00:41:11 mjl Exp $
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
  "$Id: scamper_tcp4.c,v 1.52 2011/11/17 00:41:11 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip4.h"
#include "scamper_tcp4.h"
#include "scamper_debug.h"
#include "utils.h"

/*
 * these variables are used to store a packet buffer that is allocated
 * in the scamper_udp4_probe function large enough for the largest probe
 * the routine sends
 */
static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;

static size_t tcp_mss(uint8_t *buf, uint16_t mss)
{
  buf[0] = 2;
  buf[1] = 4;
  bytes_htons(buf+2, mss);
  return 4;
}

static size_t tcp_sackp(uint8_t *buf)
{
  buf[0] = 4;
  buf[1] = 2;
  return 2;
}

static size_t tcp_nop(uint8_t *buf)
{
  buf[0] = 1;
  return 1;
}

static size_t tcp_ts(uint8_t *buf, const scamper_probe_t *probe)
{
  buf[0] = 8;
  buf[1] = 10;
  bytes_htonl(buf+2, probe->pr_tcp_tsval);
  bytes_htonl(buf+6, probe->pr_tcp_tsecr);
  return 10;
}

static void tcp_cksum(scamper_probe_t *probe, struct tcphdr *tcp, size_t len)
{
  uint16_t *w;
  int sum = 0;

  /*
   * the TCP checksum includes a checksum calculated over a psuedo header
   * that includes the src and dst IP addresses, the protocol type, and
   * the TCP length.
   */
  w = probe->pr_ip_src->addr;
  sum += *w++; sum += *w++;
  w = probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++;
  sum += htons(len);
  sum += htons(IPPROTO_TCP);

  /* compute the checksum over the body of the TCP message */
  w = (uint16_t *)tcp;
  while(len > 1)
    {
      sum += *w++;
      len -= 2;
    }

  if(len != 0)
    {
      sum += ((uint8_t *)w)[0];
    }

  /* fold the checksum */
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if((tcp->th_sum = ~sum) == 0)
    {
      tcp->th_sum = 0xffff;
    }

  return;
}

static void tcp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct tcphdr *tcp = (struct tcphdr *)buf;
  size_t tcphlen = 20;

  tcp->th_sport = htons(probe->pr_tcp_sport);
  tcp->th_dport = htons(probe->pr_tcp_dport);
  tcp->th_seq   = htonl(probe->pr_tcp_seq);
  tcp->th_ack   = htonl(probe->pr_tcp_ack);
  tcp->th_flags = probe->pr_tcp_flags;
  tcp->th_win   = htons(probe->pr_tcp_win);
  tcp->th_sum   = 0;
  tcp->th_urp   = 0;

  if(probe->pr_tcp_flags & TH_SYN)
    {
      if(probe->pr_tcp_mss != 0)
	tcphlen += tcp_mss(buf+tcphlen, probe->pr_tcp_mss);
      if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_SACK) != 0)
	tcphlen += tcp_sackp(buf+tcphlen);
    }

  if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_TS) != 0)
    tcphlen += tcp_ts(buf+tcphlen, probe);

  while((tcphlen % 4) != 0)
    tcphlen += tcp_nop(buf+tcphlen);

#ifndef _WIN32
  tcp->th_off   = tcphlen >> 2;
  tcp->th_x2    = 0;
#else
  tcp->th_offx2 = ((tcphlen >> 2) << 4);
#endif

  /* if there is data to include in the payload, copy it in now */
  if(probe->pr_len > 0)
    {
      memcpy(buf + tcphlen, probe->pr_data, probe->pr_len);
    }

  /* compute the checksum over the tcp portion of the probe */
  tcp_cksum(probe, tcp, tcphlen + probe->pr_len);

  return;
}

size_t scamper_tcp4_hlen(scamper_probe_t *probe)
{
  size_t len = 20;
  if(probe->pr_tcp_mss != 0)
    len += 4;
  if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_SACK) != 0)
    len += 2;
  if((probe->pr_tcp_opts & SCAMPER_PROBE_TCPOPT_TS) != 0)
    len += 10;
  while((len % 4) != 0)
    len++;
  return len;
}

int scamper_tcp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t ip4hlen, req;
  int rc = 0;

  ip4hlen = *len;
  scamper_ip4_build(probe, buf, &ip4hlen);
  req = ip4hlen + scamper_tcp4_hlen(probe) + probe->pr_len;

  if(req <= *len)
    tcp4_build(probe, buf + ip4hlen);
  else
    rc = -1;

  *len = req;
  return rc;
}

int scamper_tcp4_probe(scamper_probe_t *pr)
{
  struct sockaddr_in sin4;
  int                i;
  char               addr[128];
  size_t             ip4hlen, tcphlen, len, tmp;

#if !defined(IP_HDR_HTONS)
  struct ip         *ip;
#endif

  assert(pr != NULL);
  assert(pr->pr_ip_proto == IPPROTO_TCP);
  assert(pr->pr_ip_dst != NULL);
  assert(pr->pr_ip_src != NULL);
  assert(pr->pr_len > 0 || pr->pr_data == NULL);

  /* compute length, for sake of readability */
  scamper_ip4_hlen(pr, &ip4hlen);
  tcphlen = scamper_tcp4_hlen(pr);
  len = ip4hlen + tcphlen + pr->pr_len;

  i = len;
  if(setsockopt(pr->pr_fd, SOL_SOCKET, SO_SNDBUF, (char *)&i, sizeof(i)) == -1)
    {
      printerror(errno,strerror,__func__,"could not set buffer to %d bytes",i);
      return -1;
    }

  if(pktbuf_len < len)
    {
      if(realloc_wrap((void **)&pktbuf, len) != 0)
	{
	  printerror(errno, strerror, __func__, "could not realloc");
	  return -1;
	}
      pktbuf_len = len;
    }

  tmp = len;
  scamper_ip4_build(pr, pktbuf, &tmp);

#if !defined(IP_HDR_HTONS)
  ip = (struct ip *)pktbuf;
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  tcp4_build(pr, pktbuf + ip4hlen);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, pr->pr_ip_dst->addr, 0);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&pr->pr_tx);

  i = sendto(pr->pr_fd, pktbuf, len, 0, (struct sockaddr *)&sin4,
	     sizeof(struct sockaddr_in));

  if(i < 0)
    {
      /* error condition, could not send the packet at all */
      pr->pr_errno = errno;
      printerror(pr->pr_errno, strerror, __func__,
		 "could not send to %s (%d ttl, %d dport, %d len)",
		 scamper_addr_tostr(pr->pr_ip_dst, addr, sizeof(addr)),
		 pr->pr_ip_ttl, pr->pr_tcp_dport, len);
      return -1;
    }
  else if((size_t)i != len)
    {
      /* error condition, sent a portion of the probe */
      fprintf(stderr,
	      "scamper_tcp4_probe: sent %d bytes of %d byte packet to %s",
	      i, (int)len,
	      scamper_addr_tostr(pr->pr_ip_dst, addr, sizeof(addr)));
      return -1;
    }

  return 0;
}

void scamper_tcp4_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

void scamper_tcp4_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_tcp4_open(const void *addr, int sport)
{
  struct sockaddr_in sin4;
  char tmp[32];
  int opt, fd = -1;

  if((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
      printerror(errno, strerror, __func__, "could not open socket");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) != 0)
    {
      printerror(errno, strerror, __func__, "could not set SO_REUSEADDR");
      goto err;
    }

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      if(addr == NULL || addr_tostr(AF_INET, addr, tmp, sizeof(tmp)) == NULL)
	printerror(errno,strerror,__func__, "could not bind port %d", sport);
      else
	printerror(errno,strerror,__func__, "could not bind %s:%d", tmp, sport);
      goto err;
    }

  return fd;

 err:
  if(fd != -1) scamper_tcp4_close(fd);
  return -1;
}