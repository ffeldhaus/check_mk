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

#include "IntAggregator.h"
#include <math.h>
#include "IntColumn.h"
#include "Query.h"

void IntAggregator::consume(void *data, Query *query) {
    _count++;
    int32_t value = _column->getValue(data, query);
    switch (_operation) {
        case StatsOperation::sum:
        case StatsOperation::avg:
            _aggr += value;
            break;

        case StatsOperation::suminv:
        case StatsOperation::avginv:
            _sumq += 1.0 / static_cast<double>(value);
            break;

        case StatsOperation::min:
            if (_count == 1) {
                _aggr = value;
            } else if (value < _aggr) {
                _aggr = value;
            }
            break;

        case StatsOperation::max:
            if (_count == 1) {
                _aggr = value;
            } else if (value > _aggr) {
                _aggr = value;
            }
            break;

        case StatsOperation::std:
            _aggr += value;
            _sumq += static_cast<double>(value) * static_cast<double>(value);
            break;
        case StatsOperation::count:
            break;
    }
}

void IntAggregator::output(Query *q) {
    switch (_operation) {
        case StatsOperation::sum:
        case StatsOperation::min:
        case StatsOperation::max:
            q->outputInteger64(_aggr);
            break;

        case StatsOperation::suminv:
            q->outputInteger64(_sumq);
            break;

        case StatsOperation::avg:
            q->outputDouble(double(_aggr) / _count);
            break;

        case StatsOperation::avginv:
            q->outputInteger64(_sumq / _count);
            break;

        case StatsOperation::std:
            if (_count <= 1) {
                q->outputDouble(0.0);
            } else {
                q->outputDouble(sqrt(
                    (_sumq -
                     (static_cast<double>(_aggr) * static_cast<double>(_aggr)) /
                         _count) /
                    (_count - 1)));
            }
            break;
        case StatsOperation::count:
            break;
    }
}

/* Algorithmus fuer die Standardabweichung,
   bei der man zuvor den Mittelwert nicht
   wissen muss:

   def std(l):
   sum = 0.0
   sumq = 0.0
   for x in l:
   sum += x
   sumq += x*x
   n = len(l)
   return ((sumq - sum*sum/n)/(n-1)) ** 0.5

 */
