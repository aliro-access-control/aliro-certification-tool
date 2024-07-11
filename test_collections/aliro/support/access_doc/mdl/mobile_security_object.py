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

from .device_key_info import DeviceKeyInfo
from utility import Utility
from .value_digests import ValueDigests
from .validity_info import ValidityInfo

################################################################################
class MobileSecurityObject(object):
    '''Aliro Issuer Auth.'''

    VERSION_LABEL = "1"
    '''The label for the Version field.'''

    DIGEST_ALGORITHM_LABEL = "2"
    '''The label for the optional Digest Algorithm field.'''

    VALUE_DIGESTS_LABEL = "3"
    '''The label for the Value Digests field.'''

    DEVICE_KEY_INFO_LABEL = "4"
    '''The label for the Device Key Info field.'''

    DOC_TYPE_LABEL = "5"
    '''The label for the Doc Type field.'''

    VALIDITY_INFO_LABEL = "6"
    '''The label for the Validity Info field.'''

    TIME_VERIFICATION_REQUIRED_LABEL = "7"
    '''The label for the required Time Verification Required field.'''


    DOC_TYPE_ALIRO_ACCESS = "aliro-a"
    '''The DocType for the Aliro Access Document.'''

    DOC_TYPE_ALIRO_REVOCATION = "aliro-r"
    '''The Doctype for the Aliro Revocation Document.'''

    VERSION_DEFAULT = "1.0"
    '''The default data structure version.'''

    DIGEST_ALGORITHM_DEFAULT = "SHA-256"
    '''The default digest algorithm.'''

    ############################################################################
    def __init__(self):
        self.__version : str = MobileSecurityObject.VERSION_DEFAULT
        self.__digest_algorithm : str = MobileSecurityObject.DIGEST_ALGORITHM_DEFAULT
        self.__value_digests : ValueDigests = ValueDigests()
        self.__device_key_info : DeviceKeyInfo = DeviceKeyInfo()
        self.__doc_type : str = MobileSecurityObject.DOC_TYPE_ALIRO_ACCESS
        self.__validity_info : ValidityInfo = ValidityInfo()
        return

    ############################################################################
    @property
    def version(self) -> str:
        '''Get the version.'''
        return self.__version

    @version.setter
    def version(self, val : str) -> None:
        '''Set the version.'''
        assert(isinstance(val, str))
        self.__version = str(val)

    ############################################################################
    @property
    def digest_algorithm(self) -> str:
        '''Get the digest algorithm.'''
        return self.__digest_algorithm

    @digest_algorithm.setter
    def digest_algorithm(self, val : str) -> None:
        '''Set the digest algorithm.'''
        assert(isinstance(val, str))
        self.__digest_algorithm = str(val)

    ############################################################################
    @property
    def value_digests(self) -> ValueDigests:
        '''Get the value digests.'''
        return self.__value_digests

    ############################################################################
    @property
    def device_key_info(self) -> DeviceKeyInfo:
        '''Get the device key information.'''
        return self.__device_key_info

    @device_key_info.setter
    def v(self, val : DeviceKeyInfo) -> None:
        '''Set the device key information.'''
        assert(isinstance(val, DeviceKeyInfo))
        self.__device_key_info = val

    ############################################################################
    @property
    def doc_type(self) -> str:
        '''Get the document type.'''
        return self.__doc_type

    @doc_type.setter
    def doc_type(self, val : str) -> None:
        '''Set the document type.'''
        assert(isinstance(val, str))
        self.__doc_type = str(val)

    ############################################################################
    @property
    def validity_info(self) -> ValidityInfo:
        '''Get the validity information.'''
        return self.__validity_info

    @validity_info.setter
    def validity_info(self, val : ValidityInfo) -> None:
        '''Set the validity information.'''
        assert(isinstance(val, ValidityInfo))
        self.__validity_info = ValidityInfo(val)

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the MobileSecurityObject contains valid fields,
           otherwise returns False.'''

        # Verify the Version field.
        if (len(self.__version) == 0):
            return False

        # Verify the Digest Algorithm field.
        if (len(self.__digest_algorithm) == 0):
            return False

        # Verify the Value Digests field.
        if (len(self.__digest_algorithm) == 0):
            return False

        # Verify the Device Key Info field.
        if not self.__device_key_info.is_valid():
            return False

        # Verify the DocType field.
        if (len(self.__doc_type) == 0):
            return False

        # Verify the Validity Info field.
        if not self.__validity_info.is_valid():
            return False

        # The mobile security object is valid.
        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the MobileSecurityObject to a dictionary.'''
        if not self.is_valid():
            return None

        mobile_security_object_dict = {}

        # Encode the Version field.
        mobile_security_object_dict[MobileSecurityObject.VERSION_LABEL] = str(self.__version)

        # Encode the Digest Algorithm field.
        mobile_security_object_dict[MobileSecurityObject.DIGEST_ALGORITHM_LABEL] = str(self.__digest_algorithm)

        # Encode the Value Digests field.
        mobile_security_object_dict[MobileSecurityObject.VALUE_DIGESTS_LABEL] = self.__value_digests.to_dict()

        # Encode the Device Key Info field.
        mobile_security_object_dict[MobileSecurityObject.DEVICE_KEY_INFO_LABEL] = self.__device_key_info.to_dict()

        # Encode the DocType field.
        mobile_security_object_dict[MobileSecurityObject.DOC_TYPE_LABEL] = str(self.__doc_type)

        # Encode the Validity Info field.
        mobile_security_object_dict[MobileSecurityObject.VALIDITY_INFO_LABEL] = self.__validity_info.to_dict()

        return mobile_security_object_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the MobileSecurityObject to CBOR.'''
        mobile_security_object_dict = self.to_dict()
        if mobile_security_object_dict is None:
            return None
        return cbor2.dumps(mobile_security_object_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the MobileSecurityObject to JSON.'''
        mobile_security_object_dict = self.to_dict()
        if mobile_security_object_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(mobile_security_object_dict)
        return json.dumps(mobile_security_object_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the MobileSecurityObject to TLV.'''
        mobile_security_object_dict = self.to_dict()
        if mobile_security_object_dict is None:
            return None
        return Utility.dict_to_tlv(mobile_security_object_dict)
