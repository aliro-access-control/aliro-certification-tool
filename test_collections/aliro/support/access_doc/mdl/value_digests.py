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
        self.__data : dict[str, dict[int, bytearray]] = {}

    ############################################################################
    @property
    def data(self) -> dict[str, dict[int, bytearray]]:
        '''Get the Value Digests.'''
        return self.__data

    ############################################################################
    def set(self, namespace : str, id : int, digest : bytes | bytearray):
        '''Set the Digest with the given ID within the given Namespace.'''
        assert(isinstance(namespace, str))
        assert(isinstance(id, int))
        assert(isinstance(digest, (bytes, bytearray)))
        if namespace in self.__data:
            self.__data[namespace][id] = bytearray(digest)
        else:
            self.__data[namespace] = {id : bytearray(digest)}

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the ValueDigests contains valid fields,
           otherwise returns False.'''
        # Verify the Data field.
        if (type(self.__data) is not dict) or (len(self.__data) == 0):
            return False
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the ValueDigests to a dictionary.'''
        return copy.deepcopy(self.__data)

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the ValueDigests to CBOR.'''
        value_digests_dict = self.to_dict()
        if value_digests_dict is None:
            return None
        return cbor2.dumps(self.__data)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the ValueDigests to JSON.'''
        value_digests_dict = self.to_dict()
        if value_digests_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(value_digests_dict)
        return json.dumps(self.__data)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the ValueDigests to TLV.'''
        value_digests_dict = self.to_dict()
        if value_digests_dict is None:
            return None
        return Utility.dict_to_tlv(self.__data)
