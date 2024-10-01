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
import hashlib

from .issuer_signed import IssuerSigned

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.exceptions import InvalidSignature

from mdl.common.doc_types import DocTypes
from mdl.response.mobile_security_object import MobileSecurityObject
from mdl.response.sig_structure import Sig_structure

################################################################################
class Document(object):
    '''Aliro Document.'''

    DOC_TYPE_LABEL = "5"
    '''The label for the DocType field.'''

    ISSUER_SIGNED_LABEL = "1"
    '''The label for the Issuer Signed field.'''

    ############################################################################
    def __init__(self) -> None:
        self.__doc_type : str = DocTypes.ALIRO_ACCESS
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
        if not ((self.__doc_type == DocTypes.ALIRO_ACCESS) or (self.__doc_type == DocTypes.ALIRO_REVOCATION)):
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

        # Encode the Issuer Signed field.
        document_dict[Document.ISSUER_SIGNED_LABEL] = self.__issuer_signed.to_dict()

        # Encode the Doc Type field.
        document_dict[Document.DOC_TYPE_LABEL] = str(self.__doc_type)

        return document_dict

    ############################################################################
    def from_dict(self, document_dict: dict) -> bool:
        '''Parse a dictionary to populate the Document.'''
        # Clear existing Document data.
        self.__doc_type = ""
        self.__issuer_signed = IssuerSigned()

        # Get the document type from the given dictionary.
        doc_type = document_dict.get(Document.DOC_TYPE_LABEL)

        issuer_signed_dict = document_dict.get(Document.ISSUER_SIGNED_LABEL)

        # Decode the document type.
        if (doc_type is None) or (not isinstance(doc_type, str)):
            return False
        self.__doc_type = doc_type

        # Decode the issuer signed.
        issuer_signed = IssuerSigned()
        if (not issuer_signed.from_dict(issuer_signed_dict)):
            return False
        self.__issuer_signed = issuer_signed

        return self.is_valid()

    ############################################################################
    def to_cbor(self) -> bytes:
        '''Convert the Document to CBOR.'''
        document_dict = self.to_dict()
        if document_dict is None:
            return None
        return cbor2.dumps(document_dict)

    ############################################################################
    def from_cbor(self, cbor_data : (bytes | bytearray)) -> bool:
        '''Parse CBOR to populate the Document.'''
        assert(isinstance(cbor_data, (bytes, bytearray)))
        return self.from_dict(cbor2.loads(cbor_data))

    ############################################################################
    def check_signature(self, issuer_private_key) -> bool:
        mso = MobileSecurityObject()
        if not mso.from_cbor(cbor2.loads(self.issuer_signed.issuer_auth.payload).value):
            print("Mobile security object is invalid.")
            return False

        if (len(issuer_private_key) == 32):
            # Convert the raw issuer private key to a signing object.
            pk = ec.derive_private_key(int.from_bytes(issuer_private_key, byteorder='big'), ec.SECP256R1())
        else:
            # Convert the DER encoded issuer private key to a signing object.
            pk = load_der_private_key(issuer_private_key, password=None)

        # Sign the payload.
        sig_structure = Sig_structure()
        sig_structure.body_protected = self.issuer_signed.issuer_auth.protected
        sig_structure.payload = self.issuer_signed.issuer_auth.payload
        signed_data = sig_structure.to_cbor()

        public_key = pk.public_key()
        sig = self.issuer_signed.issuer_auth.signature
        r = int.from_bytes(sig[:32], byteorder='big')
        s = int.from_bytes(sig[32:], byteorder='big')
        signature = utils.encode_dss_signature(r, s)
        try:
            public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            print("Invalid signature for document.")
            return False

        # Create the issuer public key identifier by hashing "key-identifier"
        # concatenated with the issuer public key and keeping the first eight bytes.
        h = hashlib.new('sha256', "key-identifier".encode())
        h.update(pk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))

        # Check if issuer public key id is valid
        if (self.issuer_signed.issuer_auth.key_id != h.digest()[0:8]):
            print("Issuer public key id is invalid.")
            return False

        return True
