
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

#include "common/common_types.h"
#include "common/netaddr.h"
#include "config/cfg_schema.h"
#include "core/olsr_logging.h"
#include "core/olsr_subsystem.h"
#include "tools/olsr_cfg.h"
#include "tools/olsr_rfc5444.h"

#include "nhdp/nhdp.h"

#include "olsrv2/olsrv2.h"
#include "olsrv2/olsrv2_lan.h"
#include "olsrv2/olsrv2_originator_set.h"
#include "olsrv2/olsrv2_writer.h"

/* definitions */
#define _LOG_OLSRV2_NAME "olsrv2"

struct _config {
  struct netaddr originator;
  uint64_t o_hold_time;
};

/* prototypes */
static void _set_originator(const struct netaddr *originator);
static void _cb_cfg_changed(void);

/* olsrv2 configuration */
static struct cfg_schema_section _olsrv2_section = {
  .type = CFG_OLSRV2_SECTION,
  .cb_delta_handler = _cb_cfg_changed,
};

static struct cfg_schema_entry _olsrv2_entries[] = {
  CFG_MAP_NETADDR(_config, originator, "originator", "-",
      "Originator address for Routing", false, true),
  CFG_MAP_CLOCK_MIN(_config, o_hold_time, "originator_hold_time", "30.0",
    "Validity time for former Originator addresses", 100),
};

static struct _config _olsrv2_config;
static struct netaddr *_originator;
static bool _custom_originator;

enum log_source LOG_OLSRV2 = LOG_MAIN;
static struct olsr_rfc5444_protocol *_protocol;

OLSR_SUBSYSTEM_STATE(_olsrv2_state);

/**
 * Initialize OLSRv2 subsystem
 */
int
olsrv2_init(void) {
  if (olsr_subsystem_init(&_olsrv2_state)) {
    return 0;
  }

  LOG_OLSRV2 = olsr_log_register_source(_LOG_OLSRV2_NAME);

  _protocol = olsr_rfc5444_add_protocol(RFC5444_PROTOCOL, true);
  if (_protocol == NULL) {
    return -1;
  }

  if (olsrv2_writer_init(_protocol)) {
    olsr_rfc5444_remove_protocol(_protocol);
    return -1;
  }

  /* add configuration for olsrv2 section */
  cfg_schema_add_section(olsr_cfg_get_schema(), &_olsrv2_section,
      _olsrv2_entries, ARRAYSIZE(_olsrv2_entries));

  olsrv2_originatorset_init();
  olsrv2_lan_init();

  memset(&_olsrv2_config, 0, sizeof(_olsrv2_config));
  memset(&_originator, 0, sizeof(_originator));
  return 0;
}

/**
 * Cleanup OLSRv2 subsystem
 */
void
olsrv2_cleanup(void) {
  if (olsr_subsystem_cleanup(&_olsrv2_state)) {
    return;
  }

  olsrv2_originatorset_cleanup();
  olsrv2_lan_cleanup();

  cfg_schema_remove_section(olsr_cfg_get_schema(), &_olsrv2_section);
}

/**
 * @return current originator address
 */
const struct netaddr *
olsrv2_get_originator(void) {
  return _originator;
}

/**
 * Sets a new custom originator address
 * @param originator originator address
 */
void
olsrv2_set_originator(const struct netaddr *originator) {
  _custom_originator = true;
  _set_originator(originator);
}

/**
 * Resets the originator to the configured value
 */
void
olsrv2_reset_originator(void) {
  _custom_originator = false;
  _set_originator(&_olsrv2_config.originator);
}

/**
 * Sets the originator address to a new value
 * @param originator new originator
 */
static
void _set_originator(const struct netaddr *originator) {
  if (netaddr_get_address_family(_originator) != AF_UNSPEC) {
    /* add old originator to originator set */
    olsrv2_originatorset_add(_originator, _olsrv2_config.o_hold_time);
  }

  memcpy(&_originator, originator, sizeof(_originator));

  /* remove new originator from set */
  olsrv2_originatorset_remove(_originator);

  /* update NHDP originator */
  nhdp_set_originator(_originator);
}

/**
 * Callback fired when configuration changed
 */
static void
_cb_cfg_changed(void) {
  if (cfg_schema_tobin(&_olsrv2_config, _olsrv2_section.post,
      _olsrv2_entries, ARRAYSIZE(_olsrv2_entries))) {
    OLSR_WARN(LOG_OLSRV2, "Cannot convert OLSRv2 configuration.");
    return;
  }

  if (!_custom_originator) {
    /* apply new originator */
    olsrv2_reset_originator();
  }
}
