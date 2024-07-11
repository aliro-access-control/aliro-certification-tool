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

from issuer_signed import IssuerSigned
from utility import Utility

################################################################################
class Document(object):
    '''Aliro Document'''

    DOC_TYPE_LABEL = "5"
    '''The label for the DocType field.'''

    ISSUER_SIGNED_LABEL = "1"
    '''The label for the Issuer Signed field.'''


    DOC_TYPE_ALIRO_ACCESS = "aliro-a"
    '''The DocType for the Aliro Access Document.'''

    DOC_TYPE_ALIRO_REVOCATION = "aliro-r"
    '''The Doctype for the Aliro Revocation Document.'''

    ############################################################################
    def __init__(self) -> None:
        self.__doc_type : str = Document.DOC_TYPE_ALIRO_ACCESS
        self.__issuer_signed : IssuerSigned = IssuerSigned()

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
    def issuer_signed(self) -> IssuerSigned:
        '''Get the Issuer Signed field.'''
        return self.__issuer_signed

    @issuer_signed.setter
    def issuer_signed(self, val : IssuerSigned) -> None:
        '''Set the Issuer Signed field.'''
        assert(isinstance(val, IssuerSigned))
        self.__issuer_signed = val

    ############################################################################
    def is_valid(self) -> bool:
        '''Returns True if the Document contains valid fields,
           otherwise returns False.'''

        # Verify the DocType field.
        if (self.__doc_type is None) or (len(self.__doc_type) == 0):
            return False
        if not ((self.__doc_type == Document.DOC_TYPE_ALIRO_ACCESS) or (self.__doc_type == Document.DOC_TYPE_ALIRO_REVOCATION)):
            return False

        # Verify the Issuer Signed field.
        if not self.__issuer_signed.is_valid():
            return False

        return True

    ############################################################################
    def to_dict(self) -> dict:
        '''Convert the Document to a dictionary.'''
        if not self.is_valid():
            return None

        document_dict = {}

        # Encode the Signed field.
        document_dict[Document.DOC_TYPE_LABEL] = str(self.__doc_type)

        # Encode the Issuer Signed field.
        document_dict[Document.ISSUER_SIGNED_LABEL] = self.__issuer_signed.to_dict()

        return document_dict

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the Document to CBOR.'''
        document_dict = self.to_dict()
        if document_dict is None:
            return None
        return cbor2.dumps(document_dict)

    ############################################################################
    def to_json(self) -> str:
        '''Convert the Document to JSON.'''
        document_dict = self.to_dict()
        if document_dict is None:
            return None
        Utility.collection_bytes_to_hex_str(document_dict)
        return json.dumps(document_dict)

    ############################################################################
    def to_tlv(self) -> bytearray:
        '''Convert the Document to TLV.'''
        document_dict = self.to_dict()
        if document_dict is None:
            return None
        return Utility.dict_to_tlv(document_dict)
