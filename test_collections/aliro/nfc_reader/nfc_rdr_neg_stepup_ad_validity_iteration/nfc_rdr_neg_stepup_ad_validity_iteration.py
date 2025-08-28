import datetime
import hashlib

from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    INS,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.access_credential import AccessCredential
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.common import IssuerNamespaces, DocTypes
from ...support.access_doc.mdl.request import DeviceRequest
from ...support.access_doc.mdl.response import DeviceResponse
from ...support.access_doc.aliro.access import AccessData
from ...support.access_doc.mdl.response.device_response_builder import DeviceResponseBuilder, ResponseElement
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_NEG_STEPUP_AD_VALIDITY_ITERATION(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_NEG_STEPUP_AD_VALIDITY_ITERATION",
        "version": "0.0.1",
        "title": "NFC_RDR_NEG_STEPUP_AD_VALIDITY_ITERATION",
        "description": """Verify handling of validity iteration for Access Documents""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector

    # Access Credential 1 is from coniguration

    access_credential2_PuBK = bytes.fromhex(
        "0400ADBB74BBBB7E06B0A28C7D049B023796CD0F7CB9"
        "E279EC42ECFE6E415842451EB93AC5BF62D25CC1DAEA"
        "898A82B18BD813A061E21CB58B3CA93DA6DC7EC300"
    )
    access_credential2_PrivK = bytes.fromhex(
        "63BD7CE2A4ED2C35232E2C642851F3E22E6F274E1F164CA3B4D32CCA18B51FFE"
    )

    access_credential3_PuBK = bytes.fromhex(
        "046E8C3B82EDE61B910EB76711011DBDD3277F91D12A"
        "CD36C311BE743E726E176FED5565986D099C83C10F61"
        "C1962D10F94ADAD2D6F114B89E82EC350BB169664B"
    )
    access_credential3_PrivK = bytes.fromhex(
        "76F3E97A59EE71AAFB1F71751D01F4F1C564E6B35721D0F9A7296F503D52112E"
    )

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Iteration 1"),
            TestStep("Step2: Iteration 2"),
            TestStep("Step3: Iteration 3"),
            TestStep("Step4: Iteration 4"),
        ]

    def build_access_documents(self, access_credentials: list[AccessCredential]) -> list[tuple[bytes, int, int]]:
        issuer_keypair, _, self.element_id = self.access_document_data()

        access_docs = []
        access_element = AccessData()
        access_element.version = 1

        # Iteration 1: Validity Iteration = 1
        access_docs.append(
            (
                DeviceResponseBuilder.build_doc(
                    doc_type=DocTypes.ALIRO_ACCESS,
                    namespace=IssuerNamespaces.ALIRO_ACCESS,
                    data_elements=[ResponseElement(data_element_id=self.element_id, value=access_element)],
                    issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
                    device_public_key=access_credentials[0].get_access_credential_public_key().as_bytes(),
                    valid_from=datetime.datetime.now(datetime.timezone.utc),
                    valid_until=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14),
                    validity_iteration=1,
                ).to_cbor(),
                1,  # Access Credential 1
                1   # Access Credential Accepted
            )
        )

        # Iteration 2: Validity Iteration = 9
        access_docs.append(
            (
                DeviceResponseBuilder.build_doc(
                    doc_type=DocTypes.ALIRO_ACCESS,
                    namespace=IssuerNamespaces.ALIRO_ACCESS,
                    data_elements=[ResponseElement(data_element_id=self.element_id, value=access_element)],
                    issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
                    device_public_key=access_credentials[1].get_access_credential_public_key().as_bytes(),
                    valid_from=datetime.datetime.now(datetime.timezone.utc),
                    valid_until=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14),
                    validity_iteration=9,
                ).to_cbor(),
                2,  # Access Credential 2
                1,  # Access Credential Accepted
            )
        )

        # Iteration 3: Validity Iteration = 3
        access_docs.append(
            (
                DeviceResponseBuilder.build_doc(
                    doc_type=DocTypes.ALIRO_ACCESS,
                    namespace=IssuerNamespaces.ALIRO_ACCESS,
                    data_elements=[ResponseElement(data_element_id=self.element_id, value=access_element)],
                    issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
                    device_public_key=access_credentials[0].get_access_credential_public_key().as_bytes(),
                    valid_from=datetime.datetime.now(datetime.timezone.utc),
                    valid_until=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14),
                    validity_iteration=3,
                ).to_cbor(),
                1,  # Access Credential 1
                1,  # Access Credential Accepted
            )
        )

        # Iteration 4: Validity Iteration = 1
        access_docs.append(
            (
                DeviceResponseBuilder.build_doc(
                    doc_type=DocTypes.ALIRO_ACCESS,
                    namespace=IssuerNamespaces.ALIRO_ACCESS,
                    data_elements=[ResponseElement(data_element_id=self.element_id, value=access_element)],
                    issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
                    device_public_key=access_credentials[2].get_access_credential_public_key().as_bytes(),
                    valid_from=datetime.datetime.now(datetime.timezone.utc),
                    valid_until=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14),
                    validity_iteration=1,
                ).to_cbor(),
                3,  # Access Credential 3
                0,  # Access Credential Rejected
            )
        )

        for i, resp in enumerate(access_docs):
            logger.info(f"Generated Access Document: iteration {i}: {resp[0].hex()}")
        return access_docs

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        access_credential1 = self.reader_access_credential()
        access_credential2 = AccessCredential(
            access_credential_key_pair=KeyPair(
                self.access_credential2_PrivK, self.access_credential2_PuBK
            ),
            reader_id_key_list=access_credential1.reader_id_key_list
        )

        access_credential3 = AccessCredential(
            access_credential_key_pair=KeyPair(
                self.access_credential3_PrivK, self.access_credential3_PuBK
            ),
            reader_id_key_list=access_credential1.reader_id_key_list
        )

        self.access_documents = self.build_access_documents(
            [access_credential1, access_credential2, access_credential3]
        )

        self.access_cred1 = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential1],
            mailbox=0x00,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            step_up_aid_required=False,
        )

        self.access_cred2 = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential2],
            mailbox=0x00,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            step_up_aid_required=False,
        )

        self.access_cred3 = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential3],
            mailbox=0x00,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            step_up_aid_required=False,
        )

    @log_errors
    async def execute(self) -> None:
        for access_element, access_cred_index, access_cred_result in self.access_documents:
            # Prerequisites
            # Map current operating usercredential to self.usercredential so cleanup will terminate the correct one
            if access_cred_index == 1:
                self.userdevice = self.access_cred1
            elif access_cred_index == 2:
                self.userdevice = self.access_cred2
            else:
                self.userdevice = self.access_cred3

            self.userdevice.access_document = access_element

            # Display pop-up to set the Reader Device Under Test in polling mode
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Set Reader Device Under Test in NFC polling mode",
                    options={"OK": 1},
                )
            )

            # Display pop-up to put the Test Harness on the Reader device Under Test
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Bring Test Harness above Reader Device Under Test",
                    options={"OK": 1},
                )
            )

            try:
                await self.userdevice.transaction_initiation()  # including select
            except (AccessProtocolError, InvalidCommandError) as error:
                self.mark_step_failure(str(error))
                return

            try:
                cmds_auth0 = await self.userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return
            try:
                await self.userdevice.handle_auth0(cmds_auth0)
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return
            if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
                self.mark_step_failure(
                    "Userdevice is not in state auth0 standard done, either fast "
                    "transaction was requested or handling auth0 failed"
                )

            try:
                cmds_auth1 = await self.userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return

            try:
                await self.userdevice.handle_auth1(cmds_auth1)
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return

            # Envelope
            try:
                cmds_envelope = await self.userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return

            #   verify device request
            device_request = DeviceRequest()
            if not device_request.from_cbor(cmds_envelope.decrypted_payload):
                self.mark_step_failure("Failed to parse device request.")
                return

            if not device_request.is_valid():
                self.mark_step_failure("Failed to validate device request.")
                return

            found_element = False
            for doc_type, elm_req in [y for x in device_request.doc_requests for y in
                                      x.items_request.namespaces.data.items()]:
                if doc_type != "aliro-a":
                    continue
                if self.element_id in elm_req.keys():
                    found_element = True

            if not found_element:
                self.mark_step_failure(f"Reader did not request Element ID {self.element_id}")
                return

            try:
                await self.userdevice.handle_envelope(cmds_envelope)
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return

            # Test step 4 - exchange
            try:
                cmds_exchange = await self.userdevice.wait_for_command()
            except InvalidCommandError as error:
                self.mark_step_failure(str(error))
                return

            try:
                await self.userdevice.handle_exchange(cmds_exchange)
            except AccessProtocolError as error:
                self.mark_step_failure(str(error))
                return

            if cmds_exchange.reader_status.value.to_bytes(2, 'big')[0] != access_cred_result:
                self.mark_step_failure(
                    "Received incorrect EXCHANGE reader status: : 0x{:04x}".format(
                        cmds_exchange.reader_status.value
                    )
                )
                return

            await self.userdevice.transaction_termination()
            self.userdevice.storage.clear_kpersistent()  # Clear persistent cache to prevent future fast-flow
            self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_RDR_NEG_STEPUP_AD_VALIDITY_ITERATION Cleanup")
        await self.userdevice.transaction_termination()
