
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

#ifndef OLSRV2_TC_H_
#define OLSRV2_TC_H_

#include "common/avl.h"
#include "common/common_types.h"
#include "common/netaddr.h"

#include "subsystems/oonf_timer.h"

#include "nhdp/nhdp_domain.h"
#include "nhdp/nhdp.h"

#include "olsrv2/olsrv2_routing.h"

enum olsrv2_target_type {
  OLSRV2_NODE_TARGET,
  OLSRV2_ADDRESS_TARGET,
  OLSRV2_NETWORK_TARGET,
};

/*
 * represents a target that can be reached through a tc node.
 *
 * Might be another tc node, a neighbor address or an attached
 * network.
 */
struct olsrv2_tc_target {
  /* address or prefix of this node of the topology graph */
  struct netaddr addr;

  /* type of target */
  enum olsrv2_target_type type;

  /* internal data for dijkstra run */
  struct olsrv2_dijkstra_node _dijkstra;
};

/*
 * represents a tc node which might be connected to other
 * nodes and endpoints.
 */
struct olsrv2_tc_node {
  /* substructure to define target for Dijkstra Algorithm */
  struct olsrv2_tc_target target;

  /* answer set number */
  uint16_t ansn;

  /* reported interval time */
  uint64_t interval_time;

  /* time until this node has to be removed */
  struct oonf_timer_entry _validity_time;

  /* tree of olsrv2_tc_edges */
  struct avl_tree _edges;

  /* tree of olsrv2_tc_attached_networks */
  struct avl_tree _endpoints;

  /* node for tree of tc_nodes */
  struct avl_node _originator_node;
};

/* represents an edge between two tc nodes */
struct olsrv2_tc_edge {
  /* pointer to source of edge */
  struct olsrv2_tc_node *src;

  /* pointer to destination of edge */
  struct olsrv2_tc_node *dst;

  /* pointer to inverse edge */
  struct olsrv2_tc_edge *inverse;

  /* link cost of edge */
  uint32_t cost[NHDP_MAXIMUM_DOMAINS];

  /* answer set number which set this edge */
  uint16_t ansn;

  /*
   * true if this link is only virtual
   * (it only exists because the inverse edge was received).
   */
  bool virtual;

  /* node for tree of source node */
  struct avl_node _node;
};

/*
 * represents a connection from a tc node to
 * an endpoint, either a neighbor address or an attached network
 */
struct olsrv2_tc_attachment {
  /* pointer to source of edge */
  struct olsrv2_tc_node *src;

  /* pointer to destination of edge */
  struct olsrv2_tc_endpoint *dst;

  /* link cost of edge */
  uint32_t cost[NHDP_MAXIMUM_DOMAINS];

  /* distance to attached network */
  uint8_t distance[NHDP_MAXIMUM_DOMAINS];

  /* answer set number which set this edge */
  uint16_t ansn;

  /* node for tree of source node */
  struct avl_node _src_node;

  /* node for tree of endpoint nodes */
  struct avl_node _endpoint_node;
};

/*
 * reprensents an endpoint of the dijkstra graph, which
 * does not spawn new edges of the graph.
 *
 * Might be a neighbor address or an attached network
 */
struct olsrv2_tc_endpoint {
  /* substructure to define target for Dijkstra Algorithm */
  struct olsrv2_tc_target target;

  /* tree of attached networks */
  struct avl_tree _attached_networks;

  /* node for global tree of endpoints */
  struct avl_node _node;
};

EXPORT extern struct avl_tree olsrv2_tc_tree;
EXPORT extern struct avl_tree olsrv2_tc_endpoint_tree;

void olsrv2_tc_init(void);
void olsrv2_tc_cleanup(void);

EXPORT struct olsrv2_tc_node *olsrv2_tc_node_add(
    struct netaddr *, uint64_t vtime, uint16_t ansn);
EXPORT void olsrv2_tc_node_remove(struct olsrv2_tc_node *);

EXPORT struct olsrv2_tc_edge *olsrv2_tc_edge_add(
    struct olsrv2_tc_node *, struct netaddr *);
EXPORT bool olsrv2_tc_edge_remove(struct olsrv2_tc_edge *);

EXPORT struct olsrv2_tc_attachment *olsrv2_tc_endpoint_add(
    struct olsrv2_tc_node *, struct netaddr *, bool mesh);
EXPORT void olsrv2_tc_endpoint_remove(
    struct olsrv2_tc_attachment *);

/**
 * @param originator originator address of a tc node
 * @return pointer to tc node, NULL if not found
 */
static INLINE struct olsrv2_tc_node *
olsrv2_tc_node_get(struct netaddr *originator) {
  struct olsrv2_tc_node *node;

  return avl_find_element(&olsrv2_tc_tree, originator, node, _originator_node);
}

/**
 * @param prefix network prefix of tc endpoint
 * @return pointer to tc endpoint, NULL if not found
 */
static inline struct olsrv2_tc_endpoint *
olsrv2_tc_endpoint_get(struct netaddr *prefix) {
  struct olsrv2_tc_endpoint *end;

  return avl_find_element(&olsrv2_tc_endpoint_tree, prefix, end, _node);
}
#endif /* OLSRV2_TC_H_ */
