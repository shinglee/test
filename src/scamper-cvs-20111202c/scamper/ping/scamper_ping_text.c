/*
 * scamper_ping_text.c
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Author: Matthew Luckie
 *
 * $Id: scamper_ping_text.c,v 1.4 2011/09/16 03:15:44 mjl Exp $
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
  "$Id: scamper_ping_text.c,v 1.4 2011/09/16 03:15:44 mjl Exp $";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_file.h"
#include "scamper_ping_text.h"

#include "utils.h"

static char *ping_header(const scamper_ping_t *ping)
{
  char header[192], src[64], dst[64];

  snprintf(header, sizeof(header), "ping %s to %s: %d byte packets\n",
	   scamper_addr_tostr(ping->src, src, sizeof(src)),
	   scamper_addr_tostr(ping->dst, dst, sizeof(dst)),
	   ping->probe_size);

  return strdup(header);
}

static char *ping_reply(const scamper_ping_t *ping,
			const scamper_ping_reply_t *reply)
{
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  char buf[256], a[64], rtt[32], *tcp, flags[16];
  uint8_t i;
  size_t off = 0;

  scamper_addr_tostr(reply->addr, a, sizeof(a));
  timeval_tostr(&reply->rtt, rtt, sizeof(rtt));

  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  string_concat(buf, sizeof(buf), &off,
			"%d bytes from %s, seq=%d ttl=%d time=%s ms\n",
			reply->reply_size, a, reply->probe_id,
			reply->reply_ttl, rtt);
	}
      else
	{
	  string_concat(buf, sizeof(buf), &off,
			"%d bytes from %s, seq=%d ttl=%d time=%s ms\n",
			reply->reply_size, a, reply->probe_id,
			reply->reply_ttl, rtt);
	}
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      if((reply->tcp_flags & TH_RST) != 0)
	{
	  tcp = "closed";
	}
      else if((reply->tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
	{
	  if((reply->tcp_flags & TH_ECE) != 0)
	    tcp = "open,ecn";
	  else
	    tcp = "open";
	}
      else
	{
	  snprintf(flags, sizeof(flags), "%0x02x", reply->tcp_flags);
	  tcp = flags;
	}

      string_concat(buf, sizeof(buf), &off,
		    "%d bytes from %s, seq=%d tcp=%s ttl=%d time=%s ms\n",
		    reply->reply_size, a, reply->probe_id, tcp,
		    reply->reply_ttl, rtt);
    }
  else
    {
      return NULL;
    }

  if((v4rr = reply->v4rr) != NULL)
    {
      string_concat(buf, sizeof(buf), &off, " RR: %s\n",
		    scamper_addr_tostr(v4rr->rr[0], a, sizeof(a)));
      for(i=1; i<v4rr->rrc; i++)
	string_concat(buf, sizeof(buf), &off, "     %s\n",
		      scamper_addr_tostr(v4rr->rr[i], a, sizeof(a)));
    }

  if((v4ts = reply->v4ts) != NULL)
    {
      string_concat(buf, sizeof(buf), &off, " TS: ");
      if(v4ts->ips != NULL)
	string_concat(buf, sizeof(buf), &off, "%-15s ",
		      scamper_addr_tostr(v4ts->ips[0], a, sizeof(a)));
      string_concat(buf, sizeof(buf), &off, "%d\n", v4ts->tss[0]);

      for(i=1; i<v4ts->tsc; i++)
	{
	  string_concat(buf, sizeof(buf), &off, "     ");
	  if(v4ts->ips != NULL)
	    string_concat(buf, sizeof(buf), &off, "%-15s ",
			  scamper_addr_tostr(v4ts->ips[i], a, sizeof(a)));
	  string_concat(buf, sizeof(buf), &off, "%d\n", v4ts->tss[i]);
	}
    }

  return strdup(buf);
}

static char *ping_stats(const scamper_ping_t *ping)
{
  struct timeval min, max, avg, stddev;
  uint16_t loss;
  uint32_t replies, dups;
  size_t off;
  char min_str[32], max_str[32], avg_str[32], stddev_str[32];
  char buf[512];
  char dst[64];
  int rp = 0;

  if(scamper_ping_stats(ping,&replies,&dups,&loss,&min,&max,&avg,&stddev) != 0)
    return NULL;

  if(ping->ping_sent != 0)
    rp = ((ping->ping_sent - replies) * 100) / ping->ping_sent;

  off = 0;
  string_concat(buf, sizeof(buf), &off, "--- %s ping statistics ---\n",
		scamper_addr_tostr(ping->dst, dst, sizeof(dst)));
  string_concat(buf, sizeof(buf), &off,
		"%d packets transmitted, %d packets received, ",
		ping->ping_sent, replies);
  if(dups > 0)
    string_concat(buf, sizeof(buf), &off, "+%d duplicates, ", dups);
  string_concat(buf, sizeof(buf), &off, "%d%% packet loss\n", rp);
  if(replies > 0)
    {
      string_concat(buf, sizeof(buf), &off,
		    "round-trip min/avg/max/stddev = %s/%s/%s/%s ms\n",
		    timeval_tostr(&min,    min_str,    sizeof(min_str)),
		    timeval_tostr(&avg,    avg_str,    sizeof(avg_str)),
		    timeval_tostr(&max,    max_str,    sizeof(max_str)),
		    timeval_tostr(&stddev, stddev_str, sizeof(stddev_str)));
    }

  return strdup(buf);
}

int scamper_file_text_ping_write(const scamper_file_t *sf,
				 const scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  int       fd          = scamper_file_getfd(sf);
  off_t     off         = 0;
  uint32_t  reply_count = scamper_ping_reply_count(ping);
  char     *header      = NULL;
  size_t    header_len  = 0;
  char    **replies     = NULL;
  size_t   *reply_lens  = NULL;
  char     *stats       = NULL;
  size_t    stats_len   = 0;
  char     *str         = NULL;
  size_t    len         = 0;
  size_t    wc          = 0;
  int       ret         = -1;
  uint32_t  i,j;

  /* get current position incase trunction is required */
  if(fd != 1 && (off = lseek(fd, 0, SEEK_CUR)) == -1)
    {
      return -1;
    }

  /* get the header string */
  if((header = ping_header(ping)) == NULL)
    {
      goto cleanup;
    }
  len = (header_len = strlen(header));

  /* put together a string for each reply */
  if(reply_count > 0)
    {
      if((replies    = malloc_zero(sizeof(char *) * reply_count)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * reply_count)) == NULL)
	{
	  goto cleanup;
	}

      for(i=0, j=0; i<ping->ping_sent; i++)
	{
	  reply = ping->ping_replies[i];
	  while(reply != NULL)
	    {
	      /* build string representation of this reply */
	      if((replies[j] = ping_reply(ping, reply)) == NULL)
		{
		  goto cleanup;
		}
	      len += (reply_lens[j] = strlen(replies[j]));

	      reply = reply->next;
	      j++;
	    }
	}
    }

  /* put together the summary stats */
  stats = ping_stats(ping);
  len += (stats_len = strlen(stats));

  /* allocate a string long enough to combine the above strings */
  if((str = malloc(len)) == NULL)
    {
      goto cleanup;
    }

  /* combine the strings created above */
  memcpy(str+wc, header, header_len); wc += header_len;
  for(i=0; i<reply_count; i++)
    {
      memcpy(str+wc, replies[i], reply_lens[i]); wc += reply_lens[i];
    }
  memcpy(str+wc, stats, stats_len); wc += stats_len;

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != 1)
	{
	  if(ftruncate(fd, off) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }

  ret = 0; /* we succeeded */

 cleanup:
  if(str != NULL) free(str);
  if(header != NULL) free(header);
  if(stats != NULL) free(stats);
  if(reply_lens != NULL) free(reply_lens);
  if(replies != NULL)
    {
      for(i=0; i<reply_count; i++)
	{
	  if(replies[i] != NULL) free(replies[i]);
	}
      free(replies);
    }

  return ret;
}