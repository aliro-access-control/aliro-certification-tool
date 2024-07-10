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

from utility import Utility

################################################################################
class ValueDigests(object):

    ############################################################################
    def __init__(self) -> None:
        self.__value_digests : dict[str, dict[int, bytearray]] = {}

    ############################################################################
    @property
    def value_digests(self) -> dict[str, dict[int, bytearray]]:
        '''Get the value digests.'''
        return self.__value_digests

    ############################################################################
    def update(self, namespace : str, id : int, digest : bytes | bytearray):
        assert(isinstance(namespace, str))
        assert(isinstance(id, int))
        assert(isinstance(digest, (bytes, bytearray)))
        self.__value_digests[str(namespace)][int(id)] = bytearray(digest)

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the ValueDigests to a dictionary.'''
        return copy.deepcopy(self.__value_digests)

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the ValueDigests to CBOR.'''
        value_digests_dict = self.to_dict()
        if value_digests_dict is None:
            return None
        return cbor2.dumps(self.__value_digests)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the ValueDigests to JSON.'''
        value_digests_dict = self.to_dict()
        if value_digests_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(value_digests_dict)
        return json.dumps(self.__value_digests)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the ValueDigests to TLV.'''
        value_digests_dict = self.to_dict()
        if value_digests_dict is None:
            return None
        return Utility.dict_to_tlv(self.__value_digests)
