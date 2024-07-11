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

from access_data import AccessData
from .issuer_namespaces import IssuerNamespaces
from .issuer_signed_item import IssuerSignedItem
from revocation_data import RevocationData
from .device_response import DeviceResponse
from .document import Document

################################################################################
class DeviceResponseBuilder(object):
    '''Aliro Device Response Builder.'''

    ############################################################################
    @staticmethod
    def build(access_data_elements : list[AccessData], revocation_data_elements : list[RevocationData]) -> DeviceResponse:
        '''Build a Device Response from the given Access Data Elements and Revocation Data Elements.'''
        device_response = DeviceResponse()

        doc = DeviceResponseBuilder.__build_doc(IssuerNamespaces.ALIRO_ACCESS, Document.DOC_TYPE_ALIRO_ACCESS, access_data_elements)
        if (doc is not None):
            device_response.documents.append(doc)

        doc = DeviceResponseBuilder.__build_doc(IssuerNamespaces.ALIRO_REVOCATION, Document.DOC_TYPE_ALIRO_REVOCATION, revocation_data_elements)
        if (doc is not None):
            device_response.documents.append(doc)

        return device_response

    ############################################################################
    @staticmethod
    def __build_doc(namespace : str, doc_type : str, data_elements : list[AccessData] | list[RevocationData]) -> Document:
        '''Internal method to build a Document containing the given data elements.'''
        doc = None
        if (data_elements is not None) and (len(data_elements) > 0):
            digest_id = 1
            doc = Document()
            doc.doc_type = doc_type
            doc.issuer_signed.issuer_auth.doc_type = doc_type

            for data_element in data_elements:
                assert(isinstance(data_element, (AccessData | RevocationData)))
                issuer_signed_item = IssuerSignedItem()
                issuer_signed_item.digest_id = digest_id
                issuer_signed_item.element_identifier = str(digest_id)
                issuer_signed_item.element_value = data_element

                issuer_signed_item_bytes = issuer_signed_item.to_cbor()
                digest = hashlib.sha256(issuer_signed_item_bytes).digest()

                doc.issuer_signed.set(namespace, issuer_signed_item)
                doc.issuer_signed.issuer_auth.value_digests.set(namespace, digest_id, digest)

                digest_id += 1

            doc.issuer_signed.issuer_auth.validity_info.signed = datetime.datetime.now(datetime.timezone.utc)
            doc.issuer_signed.issuer_auth.validity_info.valid_from = datetime.datetime.now(datetime.timezone.utc) # TODO
            doc.issuer_signed.issuer_auth.validity_info.valid_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14) # TODO
            doc.issuer_signed.issuer_auth.validity_info.validity_iteration = 1 # TODO
        return doc
