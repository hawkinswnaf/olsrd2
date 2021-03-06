
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

#include "common/common_types.h"
#include "common/avl.h"
#include "common/avl_comp.h"
#include "rfc5444/rfc5444_iana.h"
#include "rfc5444/rfc5444.h"
#include "rfc5444/rfc5444_writer.h"
#include "core/oonf_logging.h"
#include "subsystems/oonf_rfc5444.h"

#include "nhdp/nhdp.h"
#include "nhdp/nhdp_interfaces.h"
#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp_writer.h"

/* constants */
enum {
  IDX_ADDRTLV_LOCAL_IF,
  IDX_ADDRTLV_LINK_STATUS,
  IDX_ADDRTLV_OTHER_NEIGHB,
};

/* prototypes */
static void _cb_addMessageHeader(
    struct rfc5444_writer *, struct rfc5444_writer_message *);
static void _cb_addMessageTLVs(struct rfc5444_writer *);
static void _cb_addAddresses(struct rfc5444_writer *);

static void _add_link_address(struct rfc5444_writer *writer,
    struct rfc5444_writer_content_provider *prv,
    struct nhdp_interface *interf, struct nhdp_naddr *naddr);
static void _add_localif_address(struct rfc5444_writer *writer,
    struct rfc5444_writer_content_provider *prv,
    struct nhdp_interface *interf, struct nhdp_interface_addr *addr);

static void _write_metric_tlv(struct rfc5444_writer *writer,
    struct rfc5444_writer_address *addr,
    struct nhdp_neighbor *neigh, struct nhdp_link *lnk,
    struct nhdp_domain *domain);

/* definition of NHDP writer */
static struct rfc5444_writer_message *_nhdp_message = NULL;

static struct rfc5444_writer_content_provider _nhdp_msgcontent_provider = {
  .msg_type = RFC5444_MSGTYPE_HELLO,
  .addMessageTLVs = _cb_addMessageTLVs,
  .addAddresses = _cb_addAddresses,
};

static struct rfc5444_writer_tlvtype _nhdp_addrtlvs[] = {
  [IDX_ADDRTLV_LOCAL_IF] =     { .type = RFC5444_ADDRTLV_LOCAL_IF },
  [IDX_ADDRTLV_LINK_STATUS] =  { .type = RFC5444_ADDRTLV_LINK_STATUS },
  [IDX_ADDRTLV_OTHER_NEIGHB] = { .type = RFC5444_ADDRTLV_OTHER_NEIGHB },
};

static struct oonf_rfc5444_protocol *_protocol;

static bool _cleanedup = false;

/**
 * Initialize nhdp writer
 */
int
nhdp_writer_init(struct oonf_rfc5444_protocol *p) {
  _protocol = p;

  _nhdp_message = rfc5444_writer_register_message(
      &_protocol->writer, RFC5444_MSGTYPE_HELLO, true, 4);
  if (_nhdp_message == NULL) {
    OONF_WARN(LOG_NHDP_W, "Could not register NHDP Hello message");
    return -1;
  }

  _nhdp_message->addMessageHeader = _cb_addMessageHeader;

  if (rfc5444_writer_register_msgcontentprovider(
      &_protocol->writer, &_nhdp_msgcontent_provider,
      _nhdp_addrtlvs, ARRAYSIZE(_nhdp_addrtlvs))) {

    OONF_WARN(LOG_NHDP_W, "Count not register NHDP msg contentprovider");
    rfc5444_writer_unregister_message(&_protocol->writer, _nhdp_message);
    return -1;
  }
  return 0;
}

/**
 * Cleanup nhdp writer
 */
void
nhdp_writer_cleanup(void) {
  /* remember we already did shut down the writer */
  _cleanedup = true;

  /* remove pbb writer */
  rfc5444_writer_unregister_content_provider(
      &_protocol->writer, &_nhdp_msgcontent_provider,
      _nhdp_addrtlvs, ARRAYSIZE(_nhdp_addrtlvs));
  rfc5444_writer_unregister_message(&_protocol->writer, _nhdp_message);
}

/**
 * Send a NHDP Hello through the specified interface. This might result
 * in both an IPv4 and IPv6 message
 * @param interf NHDP interface
 */
void
nhdp_writer_send_hello(struct nhdp_interface *ninterf) {
  enum rfc5444_result result;
  struct oonf_interface *interf;
  struct netaddr_str buf;

  if (_cleanedup) {
    /* do not send more Hellos during shutdown */
    return;
  }

  interf = nhdp_interface_get_coreif(ninterf);
  if (interf->data.loopback) {
    /* no NHDP on loopback interface */
    return;
  }

  OONF_DEBUG(LOG_NHDP_W, "Sending Hello to interface %s",
      nhdp_interface_get_name(ninterf));

  /* send IPv4 (if socket is active) */
  result = oonf_rfc5444_send_if(ninterf->rfc5444_if.interface->multicast4, RFC5444_MSGTYPE_HELLO);
  if (result < 0) {
    OONF_WARN(LOG_NHDP_W, "Could not send NHDP message to %s: %s (%d)",
        netaddr_to_string(&buf, &ninterf->rfc5444_if.interface->multicast4->dst), rfc5444_strerror(result), result);
  }

  /* send IPV6 (if socket is active) */
  result = oonf_rfc5444_send_if(ninterf->rfc5444_if.interface->multicast6, RFC5444_MSGTYPE_HELLO);
  if (result < 0) {
    OONF_WARN(LOG_NHDP_W, "Could not send NHDP message to %s: %s (%d)",
        netaddr_to_string(&buf, &ninterf->rfc5444_if.interface->multicast6->dst), rfc5444_strerror(result), result);
  }
}

/**
 * Callback to initialize the message header for a HELLO message
 * @param writer
 * @param message
 */
static void
_cb_addMessageHeader(struct rfc5444_writer *writer,
    struct rfc5444_writer_message *message) {
  struct oonf_rfc5444_target *target;
  const struct netaddr *originator;
  struct netaddr_str buf;

  if (!message->target_specific) {
    OONF_WARN(LOG_NHDP_W, "non interface-specific NHDP message!");
    return;
  }

  target = oonf_rfc5444_get_target_from_writer(writer);
  if (target != target->interface->multicast6
      && target != target->interface->multicast4) {
    OONF_WARN(LOG_NHDP_W, "Cannot generate unicast nhdp message to %s",
        netaddr_to_string(&buf, &target->dst));
    return;
  }

  /* get originator */
  if (netaddr_get_address_family(&target->dst) == AF_INET) {
    rfc5444_writer_set_msg_addrlen(writer, message, 4);
    originator = nhdp_get_originator(AF_INET);
  }
  else {
    rfc5444_writer_set_msg_addrlen(writer, message, 16);
    originator = nhdp_get_originator(AF_INET6);
  }

  OONF_DEBUG(LOG_NHDP_W, "Generate Hello on interface %s with destination %s",
      target->interface->name, netaddr_to_string(&buf, &target->dst));

  if (originator != NULL && netaddr_get_address_family(originator) != AF_UNSPEC) {
    OONF_DEBUG(LOG_NHDP_W, "Add originator %s", netaddr_to_string(&buf, originator));

    rfc5444_writer_set_msg_header(writer, message, true , false, false, false);
    rfc5444_writer_set_msg_originator(writer, message, netaddr_get_binptr(originator));
  }
  else {
    rfc5444_writer_set_msg_header(writer, message, false , false, false, false);
  }
}

/**
 * Callback to add the message TLVs to a HELLO message
 * @param writer
 * @param prv
 */
static void
_cb_addMessageTLVs(struct rfc5444_writer *writer) {
  uint8_t vtime_encoded, itime_encoded, will_encoded;
  struct nhdp_domain *domain;
  struct oonf_rfc5444_target *target;
  struct nhdp_interface *interf;
  const struct netaddr *v4_originator;
  struct oonf_interface_data *ifdata;

  target = oonf_rfc5444_get_target_from_writer(writer);

  if (target != target->interface->multicast4
      && target != target->interface->multicast6) {
    struct netaddr_str buf;
    OONF_WARN(LOG_NHDP_W, "target for NHDP is no interface multicast: %s",
        netaddr_to_string(&buf, &target->dst));
    assert(0);
  }

  interf = nhdp_interface_get(target->interface->name);
  if (interf == NULL) {
    OONF_WARN(LOG_NHDP_W, "Unknown interface for nhdp message: %s", target->interface->name);
    assert(0);
  }
  itime_encoded = rfc5444_timetlv_encode(interf->refresh_interval);
  vtime_encoded = rfc5444_timetlv_encode(interf->h_hold_time);

  rfc5444_writer_add_messagetlv(writer, RFC5444_MSGTLV_INTERVAL_TIME, 0,
      &itime_encoded, sizeof(itime_encoded));
  rfc5444_writer_add_messagetlv(writer, RFC5444_MSGTLV_VALIDITY_TIME, 0,
      &vtime_encoded, sizeof(vtime_encoded));

  /* add willingness for all domains */
  list_for_each_element(&nhdp_domain_list, domain, _node) {
    if (domain->mpr->no_default_handling) {
      continue;
    }

    will_encoded = nhdp_domain_get_willingness_tlvvalue(domain);

    rfc5444_writer_add_messagetlv(writer, RFC5444_MSGTLV_MPR_WILLING,
        domain->ext, &will_encoded, sizeof(will_encoded));
  }

  /* get v6 originator (might be unspecified) */
  v4_originator = nhdp_get_originator(AF_INET);

  /* add V4 originator to V6 message if available and interface is dualstack */
  if (_nhdp_message->addr_len == 16 && v4_originator != NULL
      && netaddr_get_address_family(v4_originator) == AF_INET) {
    rfc5444_writer_add_messagetlv(writer, NHDP_MSGTLV_IPV4ORIGINATOR, 0,
        netaddr_get_binptr(v4_originator), netaddr_get_binlength(v4_originator));
  }

  /* add mac address of local interface */
  ifdata = oonf_interface_get_data(target->interface->name, NULL);
  if (ifdata == NULL) {
    return;
  }
  rfc5444_writer_add_messagetlv(writer, NHDP_MSGTLV_MAC, 0,
      netaddr_get_binptr(&ifdata->mac), netaddr_get_binlength(&ifdata->mac));
}

/**
 * Add a rfc5444 address with localif TLV to the stream
 * @param writer
 * @param prv
 * @param interf
 * @param addr
 */
static void
_add_localif_address(struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *prv,
    struct nhdp_interface *interf, struct nhdp_interface_addr *addr) {
  struct rfc5444_writer_address *address;
  struct netaddr_str buf;
  uint8_t value;
  bool this_if;

  /* check if address of local interface */
  this_if = NULL != avl_find_element(
      &interf->_if_addresses, &addr->if_addr, addr, _if_node);

  OONF_DEBUG(LOG_NHDP_W, "Add %s (%s) to NHDP hello",
      netaddr_to_string(&buf, &addr->if_addr), this_if ? "this_if" : "other_if");

  /* generate RFC5444 address */
  address = rfc5444_writer_add_address(writer, prv->creator, &addr->if_addr, true);
  if (address == NULL) {
    OONF_WARN(LOG_NHDP_W, "Could not add address %s to NHDP hello",
        netaddr_to_string(&buf, &addr->if_addr));
    return;
  }

  /* Add LOCALIF TLV */
  if (this_if) {
    value = RFC5444_LOCALIF_THIS_IF;
  }
  else {
    value = RFC5444_LOCALIF_OTHER_IF;
  }
  rfc5444_writer_add_addrtlv(writer, address, &_nhdp_addrtlvs[IDX_ADDRTLV_LOCAL_IF],
      &value, sizeof(value), true);
}

/**
 * Add a rfc5444 address with link_status or other_neigh TLV to the stream
 * @param writer
 * @param prv
 * @param interf
 * @param naddr
 */
static void
_add_link_address(struct rfc5444_writer *writer, struct rfc5444_writer_content_provider *prv,
    struct nhdp_interface *interf, struct nhdp_naddr *naddr) {
  struct nhdp_domain *domain;
  struct rfc5444_writer_address *address;
  struct nhdp_laddr *laddr;
  struct netaddr_str buf;
  uint8_t linkstatus, otherneigh, mpr;

  /* initialize flags for default (lost address) address */
  linkstatus = 255;
  otherneigh = RFC5444_OTHERNEIGHB_LOST;

  laddr = nhdp_interface_get_link_addr(interf, &naddr->neigh_addr);
  if (!nhdp_db_neighbor_addr_is_lost(naddr)) {
    if (laddr != NULL && laddr->link->local_if == interf
        && laddr->link->status != NHDP_LINK_PENDING) {
      linkstatus = laddr->link->status;
    }

    if (naddr->neigh != NULL && naddr->neigh->symmetric > 0
        && linkstatus != RFC5444_LINKSTATUS_SYMMETRIC) {
      otherneigh = RFC5444_OTHERNEIGHB_SYMMETRIC;
    }
  }

  /* generate RFC5444 address */
  address = rfc5444_writer_add_address(writer, prv->creator, &naddr->neigh_addr, true);
  if (address == NULL) {
    OONF_WARN(LOG_NHDP_W, "Could not add address %s to NHDP hello",
        netaddr_to_string(&buf, &naddr->neigh_addr));
    return;
  }

  if (linkstatus != 255) {
    rfc5444_writer_add_addrtlv(writer, address,
          &_nhdp_addrtlvs[IDX_ADDRTLV_LINK_STATUS],
          &linkstatus, sizeof(linkstatus), false);

    OONF_DEBUG(LOG_NHDP_W, "Add %s (linkstatus=%d) to NHDP hello",
        netaddr_to_string(&buf, &naddr->neigh_addr), laddr->link->status);
  }

  if (otherneigh != 255) {
    rfc5444_writer_add_addrtlv(writer, address,
        &_nhdp_addrtlvs[IDX_ADDRTLV_OTHER_NEIGHB],
        &otherneigh, sizeof(otherneigh), false);

    OONF_DEBUG(LOG_NHDP_W, "Add %s (otherneigh=%d) to NHDP hello",
        netaddr_to_string(&buf, &naddr->neigh_addr), otherneigh);
  }

  /* add MPR tlvs */
  if (laddr != NULL) {
    list_for_each_element(&nhdp_domain_list, domain, _node) {
      if (domain->mpr->no_default_handling) {
        continue;
      }

      mpr = nhdp_domain_get_mpr_tlvvalue(domain, laddr->link);
      if (mpr != RFC5444_MPR_NOMPR) {
        rfc5444_writer_add_addrtlv(writer, address,
            &domain->_mpr_addrtlv, &mpr, sizeof(mpr), false);

        OONF_DEBUG(LOG_NHDP_W, "Add %s (mpr=%d, etx=%d) to NHDP hello",
            netaddr_to_string(&buf, &naddr->neigh_addr), mpr, domain->ext);
      }
    }
  }

  /* add linkcost TLVs */
  list_for_each_element(&nhdp_domain_list, domain, _node) {
    struct nhdp_link *lnk = NULL;
    struct nhdp_neighbor *neigh = NULL;

    if (domain->metric->no_default_handling) {
      continue;
    }

    if (linkstatus == RFC5444_LINKSTATUS_HEARD
        || linkstatus == RFC5444_LINKSTATUS_SYMMETRIC) {
      lnk = laddr->link;
    }
    if (naddr->neigh->symmetric > 0
        && (linkstatus == RFC5444_LINKSTATUS_SYMMETRIC
            || otherneigh == RFC5444_OTHERNEIGHB_SYMMETRIC)) {
      neigh = naddr->neigh;
    }

    _write_metric_tlv(writer, address, neigh, lnk, domain);
  }
}

/**
 * Write up to four metric TLVs to an address
 * @param writer rfc5444 writer
 * @param addr rfc5444 address
 * @param neigh pointer to symmetric neighbor, might be NULL
 * @param lnk pointer to symmetric link, might be NULL
 * @param handler pointer to link metric handler
 */
static void
_write_metric_tlv(struct rfc5444_writer *writer, struct rfc5444_writer_address *addr,
    struct nhdp_neighbor *neigh, struct nhdp_link *lnk,
    struct nhdp_domain *domain) {
  static const uint16_t flags[4] = {
      RFC5444_LINKMETRIC_INCOMING_LINK,
      RFC5444_LINKMETRIC_OUTGOING_LINK,
      RFC5444_LINKMETRIC_INCOMING_NEIGH,
      RFC5444_LINKMETRIC_OUTGOING_NEIGH,
  };
  struct nhdp_link_domaindata *linkdata;
  struct nhdp_neighbor_domaindata *neighdata;
  bool unsent[4];
  uint32_t metrics[4];
  uint16_t tlv_value;
  int i,j,k;

  if (lnk == NULL && neigh == NULL) {
    /* nothing to do */
    return;
  }

  /* get link metrics if available */
  unsent[0] = unsent[1] =
      (lnk != NULL && (lnk->status == NHDP_LINK_HEARD || lnk->status == NHDP_LINK_SYMMETRIC));

  if (unsent[0]) {
    linkdata = nhdp_domain_get_linkdata(domain, lnk);
    memcpy(&metrics[0], &linkdata->metric, sizeof(uint32_t)*2);
  }

  /* get neighbor metrics if available */
  unsent[2] = unsent[3] = (neigh != NULL && neigh->symmetric > 0);
  if (unsent[2]) {
    neighdata = nhdp_domain_get_neighbordata(domain, neigh);
    memcpy(&metrics[2], &neighdata->metric, sizeof(uint32_t)*2);
  }

  /* check if metric is infinite */
  for (i=0; i<4; i++) {
    if (unsent[i] && metrics[i] == RFC5444_METRIC_INFINITE) {
      unsent[i] = false;
    }
  }

  /* encode metrics */
  for (i=0; i<4; i++) {
    if (unsent[i]) {
      metrics[i] = rfc5444_metric_encode(metrics[i]);
    }
  }

  /* compress four metrics into 1-4 TLVs */
  k = 0;
  for (i=0; i<4; i++) {
    /* find first metric value which still must be sent */
    if (!unsent[i]) {
      continue;
    }

    /* create value */
    tlv_value = metrics[i];

    /* mark all metric pair that have the same linkmetric */
    for (j=i; j<4; j++) {
      if (unsent[j] && metrics[i] == metrics[j]) {
        tlv_value |= flags[j];
        unsent[j] = false;
      }
    }

    OONF_DEBUG(LOG_NHDP_W, "Add Metric (ext %u): 0x%04x (%u)", domain->ext, tlv_value,
        rfc5444_metric_decode(metrics[i]));

    /* conversion into network byte order */
    tlv_value = htons(tlv_value);

    /* add to rfc5444 address */
    rfc5444_writer_add_addrtlv(writer, addr,
        &domain->_metric_addrtlvs[k++],
        &tlv_value, sizeof(tlv_value), true);
  }
}
/**
 * Callback to add the addresses and address TLVs to a HELLO message
 * @param writer
 */
void
_cb_addAddresses(struct rfc5444_writer *writer) {
  struct oonf_rfc5444_target *target;

  struct nhdp_interface *interf;
  struct nhdp_interface_addr *addr;
  struct nhdp_naddr *naddr;

  /* have already be checked for message TLVs, so they cannot be NULL */
  target = oonf_rfc5444_get_target_from_writer(writer);
  interf = nhdp_interface_get(target->interface->name);

  /* transmit interface addresses first */
  avl_for_each_element(&nhdp_ifaddr_tree, addr, _global_node) {
    if (addr->removed) {
      continue;
    }
    if (netaddr_get_address_family(&addr->if_addr)
        == netaddr_get_address_family(&target->dst)) {
      _add_localif_address(writer, &_nhdp_msgcontent_provider, interf, addr);
    }
  }

  /* then transmit neighbor addresses */
  avl_for_each_element(&nhdp_naddr_tree, naddr, _global_node) {
    if (netaddr_get_address_family(&naddr->neigh_addr)
        == netaddr_get_address_family(&target->dst)) {
      _add_link_address(writer, &_nhdp_msgcontent_provider, interf, naddr);
    }
  }
}
