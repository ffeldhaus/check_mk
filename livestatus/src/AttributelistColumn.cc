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

#include "AttributelistColumn.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include "AttributelistFilter.h"
#include "Query.h"
#include "logger.h"
#include "nagios.h"
#include "opids.h"
#include "strutil.h"
class Filter;

using std::string;
using std::vector;

struct al_entry {
    const char *name;
    unsigned long bitvalue;
};

struct al_entry al_entries[] = {
    {"notifications_enabled", MODATTR_NOTIFICATIONS_ENABLED},
    {"active_checks_enabled", MODATTR_ACTIVE_CHECKS_ENABLED},
    {"passive_checks_enabled", MODATTR_PASSIVE_CHECKS_ENABLED},
    {"event_handler_enabled", MODATTR_EVENT_HANDLER_ENABLED},
    {"flap_detection_enabled", MODATTR_FLAP_DETECTION_ENABLED},
    {"failure_prediction_enabled", MODATTR_FAILURE_PREDICTION_ENABLED},
    {"performance_data_enabled", MODATTR_PERFORMANCE_DATA_ENABLED},
    {"obsessive_handler_enabled", MODATTR_OBSESSIVE_HANDLER_ENABLED},
    {"event_handler_command", MODATTR_EVENT_HANDLER_COMMAND},
    {"check_command", MODATTR_CHECK_COMMAND},
    {"normal_check_interval", MODATTR_NORMAL_CHECK_INTERVAL},
    {"retry_check_interval", MODATTR_RETRY_CHECK_INTERVAL},
    {"max_check_attempts", MODATTR_MAX_CHECK_ATTEMPTS},
    {"freshness_checks_enabled", MODATTR_FRESHNESS_CHECKS_ENABLED},
    {"check_timeperiod", MODATTR_CHECK_TIMEPERIOD},
    {"custom_variable", MODATTR_CUSTOM_VARIABLE},
    {"notification_timeperiod", MODATTR_NOTIFICATION_TIMEPERIOD},
    {nullptr, 0}};

int32_t AttributelistColumn::getValue(void *data, Query * /*unused*/) {
    char *p = reinterpret_cast<char *>(shiftPointer(data));
    if (p == nullptr) {
        return 0;
    }
    auto ptr = reinterpret_cast<int *>(p + _offset);
    return *reinterpret_cast<int32_t *>(ptr);
}

void AttributelistColumn::output(void *data, Query *query) {
    unsigned long mask = static_cast<unsigned long>(getValue(data, nullptr));
    if (_show_list) {
        unsigned i = 0;
        bool first = true;
        query->outputBeginList();
        while (al_entries[i].name != nullptr) {
            if ((mask & al_entries[i].bitvalue) != 0u) {
                if (!first) {
                    query->outputListSeparator();
                } else {
                    first = false;
                }
                query->outputString(al_entries[i].name);
            }
            i++;
        }
        query->outputEndList();
    } else {
        query->outputUnsignedLong(mask);
    }
}

string AttributelistColumn::valueAsString(void *data, Query * /*unused*/) {
    unsigned long mask = static_cast<unsigned long>(getValue(data, nullptr));
    char s[16];
    snprintf(s, 16, "%lu", mask);
    return string(s);
}

Filter *AttributelistColumn::createFilter(Query *query,
                                          RelationalOperator relOp,
                                          const string &value) {
    unsigned long ref = 0;
    if (isdigit(value[0]) != 0) {
        ref = strtoul(value.c_str(), nullptr, 10);
    } else {
        vector<char> value_vec(value.begin(), value.end());
        value_vec.push_back('\0');
        char *scan = &value_vec[0];
        char *t;
        while ((t = next_token(&scan, ',')) != nullptr) {
            unsigned i = 0;
            while (al_entries[i].name != nullptr) {
                if (strcmp(t, al_entries[i].name) == 0) {
                    ref |= al_entries[i].bitvalue;
                    break;
                }
                i++;
            }
            if (al_entries[i].name == nullptr) {
                logger(LG_INFO,
                       "Ignoring invalid value '%s' for attribute list", t);
            }
        }
    }
    return new AttributelistFilter(query, this, relOp, ref);
}
