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

#ifndef TimePointerColumn_h
#define TimePointerColumn_h

#include "config.h"  // IWYU pragma: keep
#include <string>
#include "Column.h"
#include "IntPointerColumn.h"
#include "opids.h"
class Filter;
class Query;

class TimePointerColumn : public IntPointerColumn {
public:
    TimePointerColumn(std::string name, std::string description, int *number,
                      int indirect_offset = -1, int extra_offset = -1)
        : IntPointerColumn(name, description, number, indirect_offset,
                           extra_offset) {}
    void output(void *data, Query *query) override;
    ColumnType type() override { return ColumnType::time; }
    Filter *createFilter(Query *query, RelationalOperator relOp,
                         const std::string &value) override;
};

#endif  // TimePointerColumn_h
