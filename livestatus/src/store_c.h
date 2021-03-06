// +------------------------------------------------------------------+
// |             ____ _               _        __  __ _  __           |
// |            / ___| |__   ___  ___| | __   |  \/  | |/ /           |
// |           | |   | '_ \ / _ \/ __| |/ /   | |\/| | ' /            |
// |           | |___| | | |  __/ (__|   <    | |  | | . \            |
// |            \____|_| |_|\___|\___|_|\_\___|_|  |_|_|\_\           |
// |                                                                  |
// | Copyright Mathias Kettner 2014             mk@mathias-kettner.de |
// +------------------------------------------------------------------+
//
// This file is part of Check_MK.
// The official homepage is at http://mathias-kettner.de/check_mk.
//
// check_mk is free software;  you can redistribute it and/or modify it
// under the  terms of the  GNU General Public License  as published by
// the Free Software Foundation in version 2.  check_mk is  distributed
// in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
// out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
// PARTICULAR PURPOSE. See the  GNU General Public License for more de-
// tails. You should have  received  a copy of the  GNU  General Public
// License along with GNU Make; see the file  COPYING.  If  not,  write
// to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
// Boston, MA 02110-1301 USA.

#ifndef store_c_h
#define store_c_h

#include "config.h"  // IWYU pragma: keep
#include <time.h>
#include "nagios.h"

#ifdef __cplusplus
extern "C" {
#endif

void store_init();
void store_deinit();
void store_register_comment(nebstruct_comment_data *);
void store_register_downtime(nebstruct_downtime_data *);
int store_answer_request(void *ib, void *ob);
void *create_outputbuffer();
void flush_output_buffer(void *ob, int fd, int *termination_flag);
void delete_outputbuffer(void *);
void *create_inputbuffer(int fd, const int *termination_flag);
void delete_inputbuffer(void *);
void queue_add_connection(int cc);
int queue_pop_connection();
void queue_terminate();
void update_timeperiods_cache(time_t);
void log_timeperiods_cache();
host *getHostByDesignation(const char *designation);

#ifdef __cplusplus
}
#endif

#endif /* store_c_h */
