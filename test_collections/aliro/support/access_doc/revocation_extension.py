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

from extension_data import ExtensionData
from utility import Utility

################################################################################
class RevocationExtension(object):
    EXTENSION_ID_LABEL = 0
    '''The label for the Extension ID field.'''

    VERSION_LABEL = 1
    '''The label for the Version field.'''

    DATA_LABEL = 2
    '''The label for the Data field.'''

    ############################################################################
    def __init__(self):
        self.__id : int = 0
        self.__version : int = 0
        self.__data : ExtensionData = None
        return

    ############################################################################
    @property
    def id(self) -> int:
        '''Get the Extension ID.'''
        return self.__id

    @id.setter
    def id(self, val : int) -> None:
        '''Set the Extension ID.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__id = val

    ############################################################################
    @property
    def version(self) -> int:
        '''Get the Version.'''
        return self.__version

    @version.setter
    def version(self, val : int) -> None:
        '''Set the Version.'''
        assert(isinstance(val, int))
        assert(val >= 0)
        self.__version = val

    ############################################################################
    @property
    def data(self) -> ExtensionData:
        '''Get the Extension Data.'''
        return self.__data

    @data.setter
    def data(self, val : ExtensionData) -> None:
        '''Set the Extension Data.'''
        assert(isinstance(val, ExtensionData))
        self.__data = val

    ############################################################################
    def is_valid(self) -> bool:
        # Verify the ID.
        if (type(self.id) is not int) or (self.id < 0):
            return False

        # Verify the Version.
        if (type(self.version) is not int) or (self.version < 0):
            return False

        # Verify the Data.
        if (self.data is None) or (not self.data.is_valid()):
            return False

        # The revocation extension is valid.
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the RevocationExtension to a dictionary.'''
        if not self.is_valid():
            return None

        revocation_extension_dict = {}

        # Encode the Extension ID.
        revocation_extension_dict[RevocationExtension.EXTENSION_ID_LABEL] = self.id

        # Encode the Version.
        revocation_extension_dict[RevocationExtension.VERSION_LABEL] = self.version

        # Encode the Data.
        revocation_extension_dict[RevocationExtension.DATA_LABEL] = self.data.to_dict()

        return revocation_extension_dict

    ############################################################################
    def to_cbor(self):
        '''Convert the RevocationExtension to CBOR.'''
        revocation_extension_dict = self.to_dict()
        if revocation_extension_dict is None:
            return None
        return cbor2.dumps(revocation_extension_dict)

    ############################################################################
    def to_json(self):
        '''Convert the RevocationExtension to JSON.'''
        revocation_extension_dict = self.to_dict()
        if revocation_extension_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(revocation_extension_dict)
        return json.dumps(revocation_extension_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the RevocationExtension to TLV.'''
        if not self.is_valid():
            return None

        ba = bytearray()

        # Encode the Extension ID.
        extension_id_bytes = Utility.uint_to_bytes(self.id)
        ba.append(RevocationExtension.EXTENSION_ID_LABEL)
        ba.append(len(extension_id_bytes))
        ba.extend(extension_id_bytes)

        # Encode the Version.
        version_bytes = Utility.uint_to_bytes(self.version)
        ba.append(RevocationExtension.VERSION_LABEL)
        ba.append(len(version_bytes))
        ba.extend(version_bytes)

        # Encode the Data.
        data_tlv = self.data.to_tlv()
        ba.append(RevocationExtension.DATA_LABEL)
        ba.append(len(data_tlv))
        ba.extend(data_tlv)

        return ba
