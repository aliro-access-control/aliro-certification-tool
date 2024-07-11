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
import copy
import json
import typing

from utility import Utility

################################################################################
class KeyInfo(object):

    ############################################################################
    def __init__(self) -> None:
        self.__data : dict[int, typing.Any] = {}

    ############################################################################
    @property
    def data(self) -> dict[int, typing.Any]:
        '''Get the Key Information.'''
        return self.__data

    ############################################################################
    def update(self, id : int, value : typing.Any):
        assert(isinstance(id, int))
        self.__data.update(id, value)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the KeyInfo contains valid fields,
           otherwise returns False.'''
        # Verify the Data field.
        if (type(self.__data) is not dict):
            return False
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the KeyInfo to a dictionary.'''
        if not self.is_valid():
            return None
        return copy.deepcopy(self.__data)

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the KeyInfo to CBOR.'''
        key_info_dict = self.to_dict()
        if key_info_dict is None:
            return None
        return cbor2.dumps(key_info_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the KeyInfo to JSON.'''
        key_info_dict = self.to_dict()
        if key_info_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(key_info_dict)
        return json.dumps(key_info_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the KeyInfo to TLV.'''
        key_info_dict = self.to_dict()
        if key_info_dict is None:
            return None
        return Utility.dict_to_tlv(key_info_dict)
