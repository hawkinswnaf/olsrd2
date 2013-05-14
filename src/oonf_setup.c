
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
#include "core/oonf_logging.h"
#include "core/oonf_subsystem.h"

#include "cfgio_file/cfgio_file.h"
#include "cfgparser_compact/cfgparser_compact.h"
#include "nhdp/nhdp.h"
#include "olsrv2/olsrv2.h"

#include "oonf_setup.h"

static struct oonf_subsystem *_app_subsystems[] = {
  &nhdp_subsystem,
  &olsrv2_subsystem,
};

static enum log_source _level_1_sources[] = {
  LOG_MAIN,
};

struct oonf_subsystem **
oonf_setup_get_subsystems(void) {
  return _app_subsystems;
}

size_t
oonf_setup_get_subsystem_count(void) {
  return ARRAYSIZE(_app_subsystems);
}

/**
 * @return number of logging sources for debug level 1
 */
size_t
oonf_setup_get_level1count(void) {
  return ARRAYSIZE(_level_1_sources);
}

/**
 * @return array of logging sources for debug level 1
 */
enum log_source *
oonf_setup_get_level1_logs(void) {
  return _level_1_sources;
}