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

#include "LogwatchListColumn.h"
#include <dirent.h>
#include <string.h>
#include "Query.h"
#include "mk_logwatch.h"

#ifdef CMC
#include "Host.h"
#else
#include "nagios.h"
#endif

void LogwatchListColumn::output(void *data, Query *query) {
    data = shiftPointer(data);
    if (data == nullptr) {
        return;
    }

    const char *host_name;

#ifdef CMC
    Host *host = static_cast<Host *>(data);
    host_name = host->_name;
#else
    host *hst = static_cast<host *>(data);
    host_name = hst->name;
#endif

    query->outputBeginList();
    std::string path = mk_logwatch_path_of_host(host_name);
    if (path != "") {
        DIR *dir = opendir(path.c_str());
        if (dir != nullptr) {
            struct dirent de;
            struct dirent *dep;
            bool first = true;

            while (true) {
                readdir_r(dir, &de, &dep);
                if (dep == nullptr) {
                    closedir(dir);
                    break;
                }
                if ((strcmp(dep->d_name, ".") == 0) ||
                    (strcmp(dep->d_name, "..") == 0)) {
                    continue;
                }

                if (first) {
                    first = false;
                } else {
                    query->outputListSeparator();
                }
                query->outputString(dep->d_name);
            }
        }
    }
    query->outputEndList();
}
