
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004-2013, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

#ifndef FF_ETX_H_
#define FF_ETX_H_

#include "common/common_types.h"
#include "core/oonf_subsystem.h"

/* definitions and constants */
enum {
  ETTFF_LINKSPEED_MINIMUM = 1024 * 1024,
  ETTFF_LINKSPEED_MAXIMUM = ETTFF_LINKSPEED_MINIMUM * 256,

  ETTFF_ETXCOST_MINIMUM   = NHDP_METRIC_DEFAULT / 16,
  ETTFF_ETXCOST_MAXIMUM   = NHDP_METRIC_DEFAULT,

  ETTFF_LINKCOST_START    = NHDP_METRIC_DEFAULT,
  ETTFF_LINKCOST_MINIMUM  =
      ETTFF_ETXCOST_MINIMUM *
      (ETTFF_LINKSPEED_MAXIMUM / ETTFF_LINKSPEED_MINIMUM),
  ETTFF_LINKCOST_MAXIMUM  = ETTFF_ETXCOST_MAXIMUM,
};

/* Configuration settings of ETTFF Metric */
struct ff_ett_config {
  /* Interval between two updates of the metric */
  uint64_t interval;

  /* length of history in 'interval sized' memory cells */
  int window;

  /* length of history window when a new link starts */
  int start_window;
};

/* a single history memory cell */
struct link_ettff_bucket {
  /* number of RFC5444 packets received in time interval */
  int received;

  /* sum of received and lost RFC5444 packets in time interval */
  int total;
};

/* Additional data for a nhdp_link for metric calculation */
struct link_ettff_data {
  /* current position in history ringbuffer */
  int activePtr;

  /* number of missed hellos based on timeouts since last received packet */
  int missed_hellos;

  /* current window size for this link */
  uint16_t window_size;

  /* last received packet sequence number */
  uint16_t last_seq_nr;

  /* timer for measuring lost hellos when no further packets are received */
  struct oonf_timer_entry hello_lost_timer;

  /* last known hello interval */
  uint64_t hello_interval;

  uint32_t average, variance;

  /* history ringbuffer */
  struct link_ettff_bucket buckets[0];
};

#define LOG_FF_ETT olsrv2_ffett_subsystem.logging
EXPORT extern struct oonf_subsystem olsrv2_ffett_subsystem;

#endif /* FF_ETX_H_ */
