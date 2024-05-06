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

import datetime

class Utility(object):
    BYTE_ORDER = 'big'
    '''The endian for serializing and deserializing values.'''

    ############################################################################
    @staticmethod
    def time_val_to_seconds(val : int | float | datetime.date | datetime.datetime) -> int:
        '''Convert the date / time to seconds since Unix epoch.'''
        assert isinstance(val, (int, float, datetime.date, datetime.datetime))
        if isinstance(val, (int, float)):
            t = int(val)
        elif type(val) is datetime.datetime:
            t = int(val.timestamp())
        elif type(val) is datetime.date:
            t = int(datetime.datetime(year=val.year, month=val.month, day=val.day).timestamp())
        else:
            raise TypeError

        if t < 0:
            t = int(0)
        return t

    ############################################################################
    @staticmethod
    def uint_to_bytes(value : int, byteorder='big') -> bytes:
        '''
        Convert a non-negative integer to an array of bytes,
        using the minimum number of bytes.
        '''
        assert isinstance(value, int)
        if (value < 0):
            return None
        length = 1
        mask = 0xFF
        while value > mask:
            mask = (mask << 8) | 0xFF
            length += 1
        return value.to_bytes(length, byteorder=byteorder)

    ############################################################################
    @staticmethod
    def bytes_to_hex_str(data) -> str:
        '''Convert an array of bytes to a hex string.'''
        assert isinstance(data, (bytes, bytearray))
        return "".join("{:02X}".format(v) for v in data)

    ############################################################################
    @staticmethod
    def collection_bytes_to_hex_str(collection : dict | list) -> None:
        '''Recursively convert all arrays of bytes within a collection to hex strings.'''
        if isinstance(collection, dict):
            for key in collection.keys():
                val = collection[key]
                if isinstance(val, (bytes, bytearray)):
                    collection[key] = Utility.bytes_to_hex_str(val)
                if isinstance(val, (list, dict)):
                    Utility.collection_bytes_to_hex_str(val)
        if isinstance(collection, list):
            for index, val in enumerate(collection):
                if isinstance(val, (bytes, bytearray)):
                    collection[index] = Utility.bytes_to_hex_str(val)
                if isinstance(val, (list, dict)):
                    Utility.collection_bytes_to_hex_str(val)
