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
import hashlib

from .issuer_namespaces import IssuerNamespaces
from .issuer_signed_item import IssuerSignedItem
from .device_response import DeviceResponse
from .document import Document
from .mobile_security_object import MobileSecurityObject

from access_data import AccessData
from revocation_data import RevocationData
from utility import Utility

from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

class ResponseElement(object):
    '''Aliro Device Response Element.'''

    ############################################################################
    def __init__(self, id : str = "", value : AccessData | RevocationData = None) -> None:
        self.__id : str = id
        self.__value : AccessData | RevocationData = value

    ############################################################################
    @property
    def id(self) -> str:
        '''Get the element identifier.'''
        return self.__id

    @id.setter
    def id(self, val : str) -> None:
        '''Set the element identifier.'''
        assert(isinstance(val, str))
        self.__id = str(val)

    ############################################################################
    @property
    def value(self) -> AccessData | RevocationData:
        '''Get the element value.'''
        return self.__value

    @value.setter
    def value(self, val : AccessData | RevocationData) -> None:
        '''Set the element value.'''
        assert(isinstance(val, (AccessData, RevocationData)))
        self.__value = val


################################################################################
class DeviceResponseBuilder(object):
    '''Aliro Device Response Builder.'''

    ############################################################################
    @staticmethod
    def build(
        access_data_elements : list[ResponseElement],
        revocation_data_elements : list[ResponseElement],
        issuer_public_key : bytes | bytearray,
        issuer_private_key : bytes | bytearray,
        device_public_key : bytes | bytearray,
        valid_from : str | int | float | datetime.date | datetime.datetime,
        valid_until : str | int | float | datetime.date | datetime.datetime,
        validity_iteration=-1) -> DeviceResponse:
        '''Build a Device Response from the given Access Data Elements and Revocation Data Elements.'''

        device_response = DeviceResponse()

        doc = DeviceResponseBuilder.__build_doc(
            IssuerNamespaces.ALIRO_ACCESS,
            Document.DOC_TYPE_ALIRO_ACCESS,
            access_data_elements,
            issuer_public_key,
            issuer_private_key,
            device_public_key,
            valid_from,
            valid_until,
            validity_iteration)

        if (doc is not None):
            device_response.documents.append(doc)

        doc = DeviceResponseBuilder.__build_doc(
            IssuerNamespaces.ALIRO_REVOCATION,
            Document.DOC_TYPE_ALIRO_REVOCATION,
            revocation_data_elements,
            issuer_public_key,
            issuer_private_key,
            device_public_key,
            valid_from,
            valid_until,
            validity_iteration)

        if (doc is not None):
            device_response.documents.append(doc)

        return device_response

    ############################################################################
    @staticmethod
    def __build_doc(
        namespace : str,
        doc_type : str,
        data_elements : list[ResponseElement],
        issuer_public_key : bytes | bytearray,
        issuer_private_key : bytes | bytearray,
        device_public_key : bytes | bytearray,
        valid_from : str | int | float | datetime.date | datetime.datetime,
        valid_until : str | int | float | datetime.date | datetime.datetime,
        validity_iteration) -> Document:
        '''Internal method to build a Document containing the given data elements.'''

        doc = None

        if (data_elements is not None) and (len(data_elements) > 0):
            digest_id = 1
            cbor_tag = bytearray([0xD8, 0x18])

            doc = Document()
            doc.doc_type = doc_type

            mso = MobileSecurityObject()
            mso.doc_type = doc_type

            (x, y) = Utility.get_ecc_key_components(device_public_key)
            mso.device_key_info.device_key.x = x
            mso.device_key_info.device_key.y = y

            mso.validity_info.signed = datetime.datetime.now(datetime.timezone.utc)
            mso.validity_info.valid_from = valid_from
            mso.validity_info.valid_until = valid_until
            mso.validity_info.validity_iteration = validity_iteration

            for data_element in data_elements:
                assert(isinstance(data_element, ResponseElement))
                issuer_signed_item = IssuerSignedItem()
                issuer_signed_item.digest_id = digest_id
                issuer_signed_item.element_identifier = data_element.id
                issuer_signed_item.element_value = data_element.value # TODO - Is the element_value supposed to be wrapped in an embedded CBOR tag? #6.24 (bstr .cbor)

                issuer_signed_item_bytes = issuer_signed_item.to_cbor(cbor_tag)
                digest = hashlib.sha256(issuer_signed_item_bytes).digest()

                doc.issuer_signed.set(namespace, issuer_signed_item_bytes)
                mso.value_digests.set(namespace, digest_id, digest)

                digest_id += 1

            doc.issuer_signed.issuer_auth.payload = mso.to_cbor(cbor_tag)

            # Convert the raw private key to a signing object.
            pk = ec.derive_private_key(int.from_bytes(issuer_private_key, byteorder="big"), ec.SECP256R1())

            # Sign the payload hash.
            sig = pk.sign(doc.issuer_signed.issuer_auth.payload, ec.ECDSA(hashes.SHA256()))

            # Convert the signature into a raw bytearray with concatenated r + s components.
            (r, s) = utils.decode_dss_signature(sig)
            sig_bytes = bytearray(int.to_bytes(r, length=32, byteorder='big'))
            sig_bytes.extend(int.to_bytes(s, length=32, byteorder='big'))

            # Set the raw signature with concatenated r + s components.
            doc.issuer_signed.issuer_auth.signature = sig_bytes

            # Create the issuer public key identifier by hashing "key-identifier"
            # concatenated with the issuer public key and keeping the first eight bytes.
            h = hashlib.new('sha256', "key-identifier".encode())
            h.update(issuer_public_key)
            doc.issuer_signed.issuer_auth.key_id = h.digest()[0:8]

        return doc
