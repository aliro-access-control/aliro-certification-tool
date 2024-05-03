#
# Copyright (c) 2024 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import cbor2
import json

from enum import IntFlag

from recurrence_rule import RecurrenceRule
from utility import Utility

################################################################################
class ScheduleFlagBits(IntFlag):
    TIME_IN_UTC = 1 << 0

################################################################################
class Schedule(object):
    START_TIME_LABEL = 0
    END_TIME_LABEL = 1
    RECURRENCE_RULE_LABEL = 2
    FLAGS_LABEL = 3

    FLAGS_BYTE_COUNT = 1
    '''The size in bytes of the Schedule Flags field.'''

    TIME_BYTE_COUNT = 4
    '''The number of bytes to represent time in seconds since the Unix epoch.'''

    ############################################################################
    def __init__(self):
        self.__flags = ScheduleFlagBits.TIME_IN_UTC
        self.__start_time : int = 0
        self.__end_time : int = 0
        self.__rrule = RecurrenceRule()
        return

    ############################################################################
    @property
    def flags(self) -> int:
        '''Get the bit flags.'''
        return self.__flags

    @flags.setter
    def flags(self, val : int) -> None:
        '''Set the bit flags.'''
        assert(isinstance(val, int))
        self.__flags = val & ((1 << (8 * Schedule.FLAGS_BYTE_COUNT)) - 1)

    ############################################################################
    @property
    def is_time_utc(self) -> bool:
        '''Returns True if the Time-in-UTC bit flag is set,
           otherwise returns False.'''
        return ((self.__flags & ScheduleFlagBits.TIME_IN_UTC) != 0)

    @is_time_utc.setter
    def is_time_utc(self, val : bool) -> None:
        '''Set or clear the Time-in-UTC bit flag.'''
        assert(isinstance(val, bool))
        if val:
            # Set the Time-in-UTC bit flag.
            self.flags |= ScheduleFlagBits.TIME_IN_UTC
        else:
            # Clear the Time-in-UTC bit flag.
            self.flags &= ~(int(ScheduleFlagBits.TIME_IN_UTC))

    ############################################################################
    @property
    def start_time(self) -> int:
        '''Get the start date / time in seconds since Unix epoch.'''
        return self.__start_time

    @start_time.setter
    def start_time(self, val) -> None:
        '''Set the start date / time in seconds since Unix epoch.'''
        self.__start_time = Utility.time_val_to_seconds(val)

    ############################################################################
    @property
    def end_time(self) -> int:
        '''Get the end date / time in seconds since Unix epoch.'''
        return self.__end_time

    @end_time.setter
    def end_time(self, val) -> None:
        '''Set the end date / time in seconds since Unix epoch.'''
        self.__end_time = Utility.time_val_to_seconds(val)

    ############################################################################
    @property
    def rrule(self) -> RecurrenceRule:
        '''Get the recurrence rule.'''
        return self.__rrule

    @rrule.setter
    def rrule(self, val : RecurrenceRule) -> None:
        '''Set the recurrence rule.'''
        assert isinstance(val, RecurrenceRule)
        self.__rrule = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the Schedule contains valid fields,
           otherwise returns False.'''
        # Verify the Flags.
        if ((self.flags & ~int(ScheduleFlagBits.TIME_IN_UTC)) != 0):
            return False

        # Verify the Start Time.
        if (self.start_time < 0) or (self.start_time > 0xFFFFFFFF):
            return False

        # Verify the End Time.
        if (self.end_time < 0) or (self.end_time > 0xFFFFFFFF):
            return False
        return (self.end_time == 0) or (self.end_time > self.start_time) or (self.rrule.is_valid())

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the Schedule to a dictionary.'''
        if not self.is_valid():
            return None

        schedule_dict = {}

        # Encode the start time.
        schedule_dict[Schedule.START_TIME_LABEL] = self.start_time

        # Encode the end time.
        if self.end_time > 0:
            schedule_dict[Schedule.END_TIME_LABEL] = self.end_time

        # Encode the recurrence rule.
        if self.rrule.is_valid():
            schedule_dict[Schedule.RECURRENCE_RULE_LABEL] = self.rrule.to_bytearray()

        # Encode the Flags.
        schedule_dict[Schedule.FLAGS_LABEL] = self.flags

        return schedule_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the Schedule to CBOR.'''
        schedule_dict = self.to_dict()
        if schedule_dict is None:
            return None
        return cbor2.dumps(schedule_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the Schedule to JSON.'''
        schedule_dict = self.to_dict()
        if schedule_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(schedule_dict)
        return json.dumps(schedule_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the Schedule to TLV.'''
        if not self.is_valid():
            return None

        ba = bytearray()

        # Encode the start time.
        ba.append(Schedule.START_TIME_LABEL)
        ba.append(Schedule.TIME_BYTE_COUNT)
        ba.extend(self.start_time.to_bytes(Schedule.TIME_BYTE_COUNT, byteorder=Utility.BYTE_ORDER))

        # Encode the end time.
        if self.end_time > 0:
            ba.append(Schedule.END_TIME_LABEL)
            ba.append(Schedule.TIME_BYTE_COUNT)
            ba.extend(self.end_time.to_bytes(Schedule.TIME_BYTE_COUNT, byteorder=Utility.BYTE_ORDER))

        # Encode the recurrence rule.
        if self.rrule.is_valid():
            ba.append(Schedule.RECURRENCE_RULE_LABEL)
            ba.append(RecurrenceRule.BYTE_COUNT)
            ba.extend(self.rrule.to_bytearray())

        # Encode the Flags.
        ba.append(Schedule.FLAGS_LABEL)
        ba.append(Schedule.FLAGS_BYTE_COUNT)
        ba.extend(self.flags.to_bytes(Schedule.FLAGS_BYTE_COUNT, byteorder=Utility.BYTE_ORDER))

        return ba
