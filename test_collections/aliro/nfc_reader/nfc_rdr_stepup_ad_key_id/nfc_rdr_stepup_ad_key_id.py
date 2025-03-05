import datetime

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
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.request import DeviceRequest
from ...support.access_doc.mdl.response import DeviceResponse
from ...support.access_doc.aliro.access import AccessData
from ...support.access_doc.mdl.response.device_response_builder import DeviceResponseBuilder, ResponseElement
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class NFC_RDR_STEPUP_AD_KEY_ID(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_RDR_STEPUP_AD_KEY_ID",
        "version": "0.0.1",
        "title": "NFC_RDR_STEPUP_AD_KEY_ID",
        "description": """Verify parsing of Access Document with Key Identifier""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Perform Expedited Standard transaction"),
            TestStep("Step2: Handle Step-up SELECT"),
            TestStep("Step3: Handle ENVELOPE command/response"),
            TestStep("Step4: Handle EXCHANGE command/response")
        ]

    def build_device_response(self, access_credential_pk: bytes) -> DeviceResponse:
        issuer_keypair, self.element_id = self.access_document_data()

        access_element = AccessData()
        access_element.version = 1

        x = DeviceResponseBuilder.build(
            [ResponseElement(data_element_id=self.element_id, value=access_element)],
            None,
            issuer_keypair.get_private_key().as_bytes(),
            access_credential_pk,
            valid_from=datetime.datetime.now(datetime.timezone.utc),
            valid_until=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14)
        )

        logger.info(f"Generated Device Response: {x.to_cbor().hex()}")
        return x


    async def setup(self) -> None:
        logger.info("This is a test case setup")
        access_credential = self.reader_access_credential()
        self.device_response = self.build_device_response(
            access_credential.get_access_credential_public_key().as_bytes()
        )

        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential],
            mailbox=0x00,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            access_document=self.device_response.to_cbor(),
            step_up_aid_required=True,
        )

    @log_errors
    async def execute(self) -> None:
        # Prerequisites
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
        self.next_step()

        # Test step 2 - select
        try:
            cmds_select = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return

        try:
            await self.userdevice.handle_select(cmds_select)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 3 - envelope
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
            self.mark_step_failure(f"User Device did not request Element ID {self.element_id}")
            return

        try:
            await self.userdevice.handle_envelope(cmds_envelope)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return

        self.next_step()

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

        logger.info(
            "Received EXCHANGE command with reader status: 0x{:04x}".format(
                cmds_exchange.reader_status.value
            )
        )

    async def cleanup(self) -> None:
        logger.info("RD_NFC_STPUP_10 Cleanup")
        await self.userdevice.transaction_termination()
