
/*
 * The olsr.org Optimized Link-State Routing daemon version 2 (olsrd2)
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

#include "common/avl.h"
#include "common/common_types.h"
#include "common/list.h"
#include "common/netaddr.h"
#include "rfc5444/rfc5444_iana.h"
#include "rfc5444/rfc5444.h"
#include "rfc5444/rfc5444_writer.h"
#include "core/oonf_logging.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_rfc5444.h"

#include "nhdp/nhdp_interfaces.h"
#include "nhdp/nhdp_db.h"
#include "nhdp/nhdp_domain.h"

#include "olsrv2/olsrv2.h"
#include "olsrv2/olsrv2_lan.h"
#include "olsrv2/olsrv2_originator.h"
#include "olsrv2/olsrv2_writer.h"

/* constants */
enum {
  IDX_ADDRTLV_NBR_ADDR_TYPE,
  IDX_ADDRTLV_GATEWAY,
};

/* Prototypes */
static void _send_tc(int af_type);
#if 0
static bool _cb_tc_interface_selector(struct rfc5444_writer *,
    struct rfc5444_writer_target *rfc5444_target, void *ptr);
#endif

static void _cb_initialize_gatewaytlv(void *);

static void _cb_addMessageHeader(
    struct rfc5444_writer *, struct rfc5444_writer_message *);
static void _cb_addMessageTLVs(struct rfc5444_writer *);
static void _cb_addAddresses(struct rfc5444_writer *);
static void _cb_finishMessageTLVs(struct rfc5444_writer *,
  struct rfc5444_writer_address *start,
  struct rfc5444_writer_address *end, bool complete);

/* definition of NHDP writer */
static struct rfc5444_writer_message *_olsrv2_message = NULL;

static struct rfc5444_writer_content_provider _olsrv2_msgcontent_provider = {
  .msg_type = RFC5444_MSGTYPE_TC,
  .addMessageTLVs = _cb_addMessageTLVs,
  .addAddresses = _cb_addAddresses,
  .finishMessageTLVs = _cb_finishMessageTLVs,
};

static struct rfc5444_writer_tlvtype _olsrv2_addrtlvs[] = {
  [IDX_ADDRTLV_NBR_ADDR_TYPE] =  { .type = RFC5444_ADDRTLV_NBR_ADDR_TYPE },
  [IDX_ADDRTLV_GATEWAY]       =  { .type = RFC5444_ADDRTLV_GATEWAY },
};

/* handling of gateway TLVs (they are domain specific) */
static struct rfc5444_writer_tlvtype _gateway_addrtlvs[NHDP_MAXIMUM_DOMAINS];

static struct oonf_class_extension _domain_listener = {
  .ext_name = "olsrv2 writer",
  .class_name = NHDP_CLASS_DOMAIN,

  .cb_add = _cb_initialize_gatewaytlv,
};

static int _send_msg_af;

static struct oonf_rfc5444_protocol *_protocol;

static bool _cleanedup = false;

/**
 * initialize olsrv2 writer
 * @param protocol rfc5444 protocol
 * @return -1 if an error happened, 0 otherwise
 */
int
olsrv2_writer_init(struct oonf_rfc5444_protocol *protocol) {
  _protocol = protocol;

  _olsrv2_message = rfc5444_writer_register_message(
      &_protocol->writer, RFC5444_MSGTYPE_TC, true, 4);
  if (_olsrv2_message == NULL) {
    OONF_WARN(LOG_OLSRV2, "Could not register OLSRV2 TC message");
    return -1;
  }

  _olsrv2_message->addMessageHeader = _cb_addMessageHeader;
  _olsrv2_message->forward_target_selector = nhdp_message_forwarding_selector;

  if (rfc5444_writer_register_msgcontentprovider(
      &_protocol->writer, &_olsrv2_msgcontent_provider,
      _olsrv2_addrtlvs, ARRAYSIZE(_olsrv2_addrtlvs))) {

    OONF_WARN(LOG_OLSRV2, "Count not register OLSRV2 msg contentprovider");
    rfc5444_writer_unregister_message(&_protocol->writer, _olsrv2_message);
    return -1;
  }

  oonf_class_extension_add(&_domain_listener);
  return 0;
}

/**
 * Cleanup olsrv2 writer
 */
void
olsrv2_writer_cleanup(void) {
  int i;

  _cleanedup = true;

  oonf_class_extension_remove(&_domain_listener);

  /* unregister address tlvs */
  for (i=0; i<NHDP_MAXIMUM_DOMAINS; i++) {
    if (_gateway_addrtlvs[i].type) {
      rfc5444_writer_unregister_addrtlvtype(&_protocol->writer, &_gateway_addrtlvs[i]);
    }
  }

  /* remove pbb writer */
  rfc5444_writer_unregister_content_provider(
      &_protocol->writer, &_olsrv2_msgcontent_provider,
      _olsrv2_addrtlvs, ARRAYSIZE(_olsrv2_addrtlvs));
  rfc5444_writer_unregister_message(&_protocol->writer, _olsrv2_message);
}

/**
 * Send a new TC message over all relevant interfaces
 */
void
olsrv2_writer_send_tc(void) {
  if (_cleanedup) {
    /* do not send more TCs during shutdown */
    return;
  }

  _send_tc(AF_INET);
  _send_tc(AF_INET6);
}

/**
 * Send a TC for a specified address family if the originator is set
 * @param af_type address family type
 */
static void
_send_tc(int af_type) {
  const struct netaddr *originator;

  originator = olsrv2_originator_get(af_type);
  if (netaddr_get_address_family(originator) == af_type) {
    _send_msg_af = af_type;
    OONF_INFO(LOG_OLSRV2_W, "Emit IPv%d TC message.", af_type == AF_INET ? 4 : 6);
    oonf_rfc5444_send_all(_protocol, RFC5444_MSGTYPE_TC, nhdp_flooding_selector);
    _send_msg_af = AF_UNSPEC;
  }
}

/**
 * initialize the gateway tlvs for a nhdp domain
 * @param ptr nhdp domain
 */
static void
_cb_initialize_gatewaytlv(void *ptr) {
  struct nhdp_domain *domain = ptr;

  _gateway_addrtlvs[domain->index].type = RFC5444_ADDRTLV_GATEWAY;
  _gateway_addrtlvs[domain->index].exttype = domain->ext;

  rfc5444_writer_register_addrtlvtype(&_protocol->writer,
      &_gateway_addrtlvs[domain->index], RFC5444_MSGTYPE_TC);
}

/**
 * Callback for rfc5444 writer to add message header for tc
 * @param writer
 * @param message
 */
static void
_cb_addMessageHeader(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *message) {
  const struct netaddr *orig;

  orig = olsrv2_originator_get(_send_msg_af);

  /* initialize message header */
  rfc5444_writer_set_msg_header(writer, message, true, true, true, true);
  rfc5444_writer_set_msg_addrlen(writer, message, netaddr_get_binlength(orig));
  rfc5444_writer_set_msg_originator(writer, message, netaddr_get_binptr(orig));
  rfc5444_writer_set_msg_hopcount(writer, message, 0);
  rfc5444_writer_set_msg_hoplimit(writer, message, 255);
  rfc5444_writer_set_msg_seqno(writer, message,
      oonf_rfc5444_get_next_message_seqno(_protocol));

  OONF_DEBUG(LOG_OLSRV2_W, "Generate TC");
}

/**
 * Callback for rfc5444 writer to add message tlvs to tc
 * @param writer
 */
static void
_cb_addMessageTLVs(struct rfc5444_writer *writer) {
  uint8_t vtime_encoded, itime_encoded;

  /* generate validity time and interval time */
  itime_encoded = rfc5444_timetlv_encode(olsrv2_get_tc_interval());
  vtime_encoded = rfc5444_timetlv_encode(olsrv2_get_tc_validity());

  /* allocate space for ANSN tlv */
  rfc5444_writer_allocate_messagetlv(writer, true, 2);

  /* add validity and interval time TLV */
  rfc5444_writer_add_messagetlv(writer, RFC5444_MSGTLV_VALIDITY_TIME, 0,
      &vtime_encoded, sizeof(vtime_encoded));
  rfc5444_writer_add_messagetlv(writer, RFC5444_MSGTLV_INTERVAL_TIME, 0,
      &itime_encoded, sizeof(itime_encoded));
}

static void
_generate_neighbor_metric_tlvs(struct rfc5444_writer *writer,
    struct rfc5444_writer_address *addr, struct nhdp_neighbor *neigh) {
  struct nhdp_neighbor_domaindata *neigh_domain;
  struct nhdp_domain *domain;
  uint32_t metric_in, metric_out;
  uint16_t metric_in_encoded, metric_out_encoded;

  list_for_each_element(&nhdp_domain_list, domain, _node) {
    neigh_domain = nhdp_domain_get_neighbordata(domain, neigh);

    metric_in = neigh_domain->metric.in;
    metric_in_encoded = rfc5444_metric_encode(metric_in);

    metric_out = neigh_domain->metric.out;
    metric_out_encoded = rfc5444_metric_encode(metric_out);

    if (!nhdp_domain_get_neighbordata(domain, neigh)->neigh_is_mpr) {
      /* just put in an empty metric so we don't need to start a second TLV */
      metric_in_encoded = 0;

      OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%04x",
          domain->ext, metric_in_encoded);
      metric_in_encoded = htons(metric_in_encoded);
      rfc5444_writer_add_addrtlv(writer, addr, &domain->_metric_addrtlvs[0],
          &metric_in_encoded, sizeof(metric_in_encoded), true);
    }
    else if (metric_in_encoded == metric_out_encoded) {
      /* incoming and outgoing metric are the same */
      if (metric_in < RFC5444_METRIC_INFINITE) {
        metric_in_encoded |= RFC5444_LINKMETRIC_INCOMING_NEIGH;
        metric_in_encoded |= RFC5444_LINKMETRIC_OUTGOING_NEIGH;

        OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%04x",
            domain->ext, metric_in_encoded);
      }

      metric_in_encoded = htons(metric_in_encoded);
      rfc5444_writer_add_addrtlv(writer, addr, &domain->_metric_addrtlvs[0],
          &metric_in_encoded, sizeof(metric_in_encoded), true);
    }
    else {
      int metric_index = 0;

      /* different metrics for incoming and outgoing link */
      if (metric_in < RFC5444_METRIC_INFINITE) {
        metric_in_encoded |= RFC5444_LINKMETRIC_INCOMING_NEIGH;

        OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%04x",
            domain->ext, metric_in_encoded);
        metric_in_encoded = htons(metric_in_encoded);
        rfc5444_writer_add_addrtlv(writer, addr,
            &domain->_metric_addrtlvs[metric_index++],
            &metric_in_encoded, sizeof(metric_in_encoded), true);
      }

      if (metric_out < RFC5444_METRIC_INFINITE) {
        metric_out_encoded |= RFC5444_LINKMETRIC_OUTGOING_NEIGH;

        OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%04x",
            domain->ext, metric_out_encoded);
        metric_out_encoded = htons(metric_out_encoded);
        rfc5444_writer_add_addrtlv(writer, addr,
          &domain->_metric_addrtlvs[metric_index++],
          &metric_out_encoded, sizeof(metric_out_encoded), true);
      }
    }
  }
}

/**
 * Callback for rfc5444 writer to add addresses and addresstlvs to tc
 * @param writer
 */
static void
_cb_addAddresses(struct rfc5444_writer *writer) {
  const struct netaddr_acl *routable_acl;
  struct rfc5444_writer_address *addr;
  struct nhdp_neighbor *neigh;
  struct nhdp_naddr *naddr;
  struct nhdp_domain *domain;
  struct olsrv2_lan_entry *lan;
  bool any_advertised;
  uint8_t nbr_addrtype_value;
  uint32_t metric_out;
  uint16_t metric_out_encoded;

#ifdef OONF_LOG_DEBUG_INFO
  struct netaddr_str buf;
#endif

  routable_acl = olsrv2_get_routable();

  /* iterate over neighbors */
  list_for_each_element(&nhdp_neigh_list, neigh, _global_node) {
    any_advertised = false;
    /* see if we have been selected as a MPR by this neighbor */
    list_for_each_element(&nhdp_domain_list, domain, _node) {
      if (nhdp_domain_get_neighbordata(domain, neigh)->local_is_mpr) {
        /* found one */
        any_advertised = true;
        break;
      }
    }

    if (!any_advertised) {
      /* we are not a MPR for this neighbor, so we don't advertise the neighbor */
      continue;
    }

    /* iterate over neighbors addresses */
    avl_for_each_element(&neigh->_neigh_addresses, naddr, _neigh_node) {
      if (netaddr_get_address_family(&naddr->neigh_addr) != _send_msg_af) {
        /* wrong address family, skip this one */
        continue;
      }

      nbr_addrtype_value = 0;

      if (netaddr_acl_check_accept(routable_acl, &naddr->neigh_addr)) {
        nbr_addrtype_value |= RFC5444_NBR_ADDR_TYPE_ROUTABLE;
      }
      // TODO: what is about MPR settings?
      if (netaddr_cmp(&neigh->originator, &naddr->neigh_addr) == 0) {
        nbr_addrtype_value |= RFC5444_NBR_ADDR_TYPE_ORIGINATOR;
      }

      if (nbr_addrtype_value == 0) {
        /* skip this address */
        OONF_DEBUG(LOG_OLSRV2_W, "Address %s is neither routable"
            " nor an originator", netaddr_to_string(&buf, &naddr->neigh_addr));
        continue;
      }

      OONF_DEBUG(LOG_OLSRV2_W, "Add address %s to TC",
          netaddr_to_string(&buf, &naddr->neigh_addr));
      addr = rfc5444_writer_add_address(writer, _olsrv2_msgcontent_provider.creator,
          &naddr->neigh_addr, false);
      if (addr == NULL) {
        OONF_WARN(LOG_OLSRV2_W, "Out of memory error for olsrv2 address");
        return;
      }

      /* add neighbor type TLV */
      OONF_DEBUG(LOG_OLSRV2_W, "Add NBRAddrType TLV with value %u", nbr_addrtype_value);
      rfc5444_writer_add_addrtlv(writer, addr, &_olsrv2_addrtlvs[IDX_ADDRTLV_NBR_ADDR_TYPE],
          &nbr_addrtype_value, sizeof(nbr_addrtype_value), false);

      /* add linkmetric TLVs */
      _generate_neighbor_metric_tlvs(writer, addr, neigh);
    }
  }

  /* Iterate over locally attached networks */
  avl_for_each_element(&olsrv2_lan_tree, lan, _node) {
    if (netaddr_get_address_family(&lan->prefix) != _send_msg_af) {
      /* wrong address family */
      continue;
    }

    OONF_DEBUG(LOG_OLSRV2_W, "Add address %s to TC",
        netaddr_to_string(&buf, &lan->prefix));
    addr = rfc5444_writer_add_address(writer, _olsrv2_msgcontent_provider.creator,
        &lan->prefix, false);
    if (addr == NULL) {
      OONF_WARN(LOG_OLSRV2_W, "Out of memory error for olsrv2 address");
      return;
    }

    /* add Gateway TLV and Metric TLV */
    list_for_each_element(&nhdp_domain_list, domain, _node) {
      metric_out = lan->data[domain->index].outgoing_metric;
      if (metric_out >= RFC5444_METRIC_INFINITE) {
        continue;
      }

      metric_out_encoded = rfc5444_metric_encode(metric_out);
      metric_out_encoded |= RFC5444_LINKMETRIC_OUTGOING_NEIGH;

      /* add Metric TLV */
      OONF_DEBUG(LOG_OLSRV2_W, "Add Linkmetric (ext %u) TLV with value 0x%04x",
          domain->ext, metric_out_encoded);
      rfc5444_writer_add_addrtlv(writer, addr, &domain->_metric_addrtlvs[0],
          &metric_out_encoded, sizeof(metric_out_encoded), false);

      /* add Gateway TLV */
      OONF_DEBUG(LOG_OLSRV2_W, "Add Gateway (ext %u) TLV with value 0x%04x",
          domain->ext, metric_out_encoded);
      rfc5444_writer_add_addrtlv(writer, addr, &_gateway_addrtlvs[domain->index],
          &lan->data[domain->index]. distance, 1, false);
    }
  }
}

/**
 * Callback triggered when tc is finished.
 * @param writer
 * @param start
 * @param end
 * @param complete
 */
static void
_cb_finishMessageTLVs(struct rfc5444_writer *writer,
    struct rfc5444_writer_address *start __attribute__((unused)),
    struct rfc5444_writer_address *end __attribute__((unused)),
    bool complete) {
  uint16_t ansn;

  /* get ANSN */
  ansn = htons(olsrv2_update_ansn());

  rfc5444_writer_set_messagetlv(writer, RFC5444_MSGTLV_CONT_SEQ_NUM,
      complete ? RFC5444_CONT_SEQ_NUM_COMPLETE : RFC5444_CONT_SEQ_NUM_INCOMPLETE,
      &ansn, sizeof(ansn));
}
