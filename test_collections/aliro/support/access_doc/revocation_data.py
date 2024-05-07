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

from enum import IntEnum

from revocation_entry import RevocationEntry
from revocation_extension import RevocationExtension
from utility import Utility

################################################################################
class RevocationChangeMode(IntEnum):
    '''Aliro Revocation Change Modes.'''

    OVERWRITE   = 0
    '''
    Erase all existing entries in the Reader's revocation list and then append
    all new entries to the Reader's revocation list.
    '''

    APPEND      = 1
    '''Append all new entries to the Reader's existing revocation list.'''

################################################################################
class RevocationData(object):
    '''Aliro Revocation Data.'''

    VERSION_LABEL = 0
    '''The label for the required Version field.'''

    CHANGE_MODE_LABEL = 1
    '''The label for the required Change Mode field.'''

    ENTRIES_LABEL = 2
    '''The label for the optional Entries field.'''

    ENTRIES_TO_REMOVE_LABEL = 3
    '''The label for the optional Entries to Remove field.'''

    EXTENSIONS_LABEL = 4
    '''The label for the optional Revocation Extensions field.'''

    ############################################################################
    def __init__(self):
        self.__version : int = 0
        self.__change_mode = RevocationChangeMode.OVERWRITE
        self.__entries : list[RevocationEntry] = []
        self.__entries_to_remove : list[RevocationEntry] = []
        self.__extensions : list[RevocationExtension] = []
        return

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
    def change_mode(self) -> RevocationChangeMode:
        '''Get the Change Mode.'''
        return self.__change_mode

    @change_mode.setter
    def change_mode(self, val : int | RevocationChangeMode) -> None:
        '''Set the Change Mode.'''
        assert(isinstance(val, (int | RevocationChangeMode)))
        assert((val == RevocationChangeMode.OVERWRITE) or (val == RevocationChangeMode.Append))
        self.__change_mode = val

    ############################################################################
    @property
    def entries(self) -> list[RevocationEntry]:
        '''Get the list of Entries.'''
        return self.__entries

    ############################################################################
    @property
    def entries_to_remove(self) -> list[RevocationEntry]:
        '''Get the list of Entries to Remove.'''
        return self.__entries_to_remove

    ############################################################################
    @property
    def extensions(self) -> list[RevocationExtension]:
        '''Get the list of Extensions.'''
        return self.__extensions

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the RevocationData contains valid fields,
           otherwise returns False.'''
        # Verify the Version.
        if (type(self.version) is not int) or (self.version < 0):
            return False

        # Verify the Change Mode.
        if (self.change_mode is None) or (self.change_mode < RevocationChangeMode.OVERWRITE) or (self.change_mode > RevocationChangeMode.APPEND):
            return False

        # Verify the Entries.
        if (self.entries is not None):
            for entry in self.entries:
                if not entry.is_valid():
                    return False

        # Verify the Entries to Remove.
        if (self.entries_to_remove is not None):
            for entry in self.entries_to_remove:
                if not entry.is_valid():
                    return False

        # Verify the Extensions.
        if (self.extensions is not None):
            for revocation_extension in self.extensions:
                if not revocation_extension.is_valid():
                    return False

        # The revocation data is valid.
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the RevocationData to a dictionary.'''
        if not self.is_valid():
            return None

        revocation_data_dict = {}

        # Encode the Version.
        revocation_data_dict[RevocationData.VERSION_LABEL] = self.version

        # Encode the Change mode.
        revocation_data_dict[RevocationData.CHANGE_MODE_LABEL] = self.change_mode

        # Encode the Entries.
        if (self.entries is not None) and (len(self.entries) > 0):
            entries_list = []
            for entry in self.entries:
                entries_list.append(entry.to_dict())
            revocation_data_dict[RevocationData.ENTRIES_LABEL] = entries_list

        # Encode the Entries to Remove.
        if (self.entries_to_remove is not None) and (len(self.entries_to_remove) > 0):
            entries_to_remove_list = []
            for entry_to_remove in self.entries_to_remove:
                entries_to_remove_list.append(entry_to_remove.to_dict())
            revocation_data_dict[RevocationData.ENTRIES_TO_REMOVE_LABEL] = entries_to_remove_list

        # Encode the Revocation Extensions.
        if (self.extensions is not None) and (len(self.extensions) > 0):
            revocation_extensions_list = []
            for revocation_extension in self.extensions:
                revocation_extensions_list.append(revocation_extension.to_dict())
            revocation_data_dict[RevocationData.EXTENSIONS_LABEL] = revocation_extensions_list

        return revocation_data_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the RevocationData to CBOR.'''
        revocation_data_dict = self.to_dict()
        if revocation_data_dict is None:
            return None
        return cbor2.dumps(revocation_data_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the RevocationData to JSON.'''
        revocation_data_dict = self.to_dict()
        if revocation_data_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(revocation_data_dict)
        return json.dumps(revocation_data_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the RevocationData to TLV.'''
        if not self.is_valid():
            return None

        ba = bytearray()

        # Encode the Version.
        version_bytes = Utility.uint_to_bytes(self.version)
        ba.append(RevocationData.VERSION_LABEL)
        ba.append(len(version_bytes))
        ba.extend(version_bytes)

        # Encode the Change Mode.
        change_mode_bytes = Utility.uint_to_bytes(int(self.change_mode))
        ba.append(RevocationData.CHANGE_MODE_LABEL)
        ba.append(len(change_mode_bytes))
        ba.extend(change_mode_bytes)

        # Encode the Entries.
        if (self.entries is not None) and (len(self.entries) > 0):
            entries_tlv = bytearray()
            for entry in self.entries:
                entries_tlv.extend(entry.to_tlv())
            ba.append(RevocationData.ENTRIES_LABEL)
            ba.append(len(entries_tlv))
            ba.extend(entries_tlv)

        # Encode the Entries to Remove.
        if (self.entries_to_remove is not None) and (len(self.entries_to_remove) > 0):
            entries_to_remove_tlv = bytearray()
            for entry_to_remove in self.entries_to_remove:
                entries_to_remove_tlv.extend(entry_to_remove.to_tlv())
            ba.append(RevocationData.ENTRIES_LABEL)
            ba.append(len(entries_to_remove_tlv))
            ba.extend(entries_to_remove_tlv)

        # Encode the Revocation Extensions.
        if (self.extensions is not None) and (len(self.extensions) > 0):
            extensions_tlv = bytearray()
            for revocation_extension in self.extensions:
                extensions_tlv.extend(revocation_extension.to_tlv())
            ba.append(RevocationData.EXTENSIONS_LABEL)
            ba.append(len(extensions_tlv))
            ba.extend(extensions_tlv)

        return ba
