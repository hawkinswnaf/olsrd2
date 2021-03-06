
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
/* initialize basic framework */

#include "common/common_types.h"

#include "app_data.h"

#include "core/oonf_libdata.h"
#include "core/oonf_logging.h"
#include "core/oonf_plugins.h"
#include "core/oonf_subsystem.h"
#include "core/os_core.h"
#include "subsystems/oonf_class.h"
#include "subsystems/oonf_clock.h"
#include "subsystems/oonf_interface.h"
#include "subsystems/oonf_layer2.h"
#include "subsystems/oonf_packet_socket.h"
#include "subsystems/oonf_socket.h"
#include "subsystems/oonf_stream_socket.h"
#include "subsystems/oonf_timer.h"
#include "subsystems/os_clock.h"
#include "subsystems/os_net.h"
#include "subsystems/os_routing.h"
#include "subsystems/os_system.h"
#include "subsystems/oonf_http.h"
#include "subsystems/oonf_rfc5444.h"
#include "subsystems/oonf_telnet.h"

#include "oonf_api_subsystems.h"

struct oonf_subsystem *used_api_subsystems[] = {
  &oonf_os_core_subsystem,
  &oonf_class_subsystem,
  &oonf_os_clock_subsystem,
  &oonf_clock_subsystem,
  &oonf_timer_subsystem,
  &oonf_socket_subsystem,
  &oonf_packet_socket_subsystem,
  &oonf_stream_socket_subsystem,
  &oonf_os_system_subsystem,
  &oonf_os_routing_subsystem,
  &oonf_os_net_subsystem,
  &oonf_interface_subsystem,
  &oonf_layer2_subsystem,
  &oonf_duplicate_set_subsystem,
  &oonf_rfc5444_subsystem,
  &oonf_telnet_subsystem,
  &oonf_http_subsystem,
};

size_t
get_used_api_subsystem_count(void) {
  return ARRAYSIZE(used_api_subsystems);
}
