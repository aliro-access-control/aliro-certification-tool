from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    STEPUP_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.certificate import Certificate
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.response import DeviceResponse
from ...support.access_doc.mdl.response.device_response import DeviceResponseStatus
from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class UD_NFC_ENVELOPE_10(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-NFC-ENVELOPE-1.0",
        "version": "0.0.1",
        "title": "UD-NFC-ENVELOPE-1.0",
        "description": """Verify conformance of User Device UT in ENVELOPE and GET RESPONSE command.""",
    }

    reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8"
        "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
        "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
    )
    reader_ePrivK = bytes.fromhex(
        "3c0f74114cd2a021e8066efbaa31dbb97ef0054272192606fd96633a04f66214"
    )
    transaction_identifier = bytes.fromhex("4165A83667AD0AF5AB115247424822E0")

    request = bytes.fromhex(
        "A2613163312E30613282A16131D818581FA2613567616C69726F2D616131A"
        "167616C69726F2D61A166666C6F6F7231F4A16131D818581FA2613567616C"
        "69726F2D726131A167616C69726F2D72A166666C6F6F7232F5"
    )

    issuer_private_key = bytearray([
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30,
        0x6B, 0x02, 0x01, 0x01, 0x04, 0x20, 0x4B, 0x45, 0xDF, 0x37,
        0xA3, 0x27, 0xA3, 0x13, 0x03, 0x11, 0x3F, 0x99, 0x65, 0xD1,
        0x4D, 0xE9, 0x4F, 0x02, 0x5F, 0x88, 0x15, 0x15, 0xE1, 0x30,
        0x34, 0xA3, 0xD8, 0xA9, 0xAC, 0x47, 0xE4, 0x3E, 0xA1, 0x44,
        0x03, 0x42, 0x00, 0x04, 0x79, 0x3E, 0x3A, 0x8F, 0x20, 0x42,
        0x8D, 0x54, 0xE7, 0x31, 0x80, 0x46, 0xD7, 0x5D, 0x05, 0xA8,
        0x73, 0x7E, 0xB6, 0xE0, 0x74, 0xE5, 0x14, 0x6A, 0x20, 0x7B,
        0xFF, 0x62, 0xDA, 0xE9, 0x0E, 0x24, 0x03, 0x9F, 0x37, 0x28,
        0x14, 0xA3, 0x12, 0xC3, 0xCB, 0x82, 0xA5, 0xA9, 0x7B, 0xB5,
        0xBF, 0xA9, 0xE6, 0x23, 0xA3, 0xCC, 0x88, 0x6B, 0x09, 0xDC,
        0x13, 0xD5, 0x3E, 0xF0, 0xDA, 0x7D, 0xE7, 0xBD])

    # Uncompressed reader public key with 0x04 prefix.
    reader_public_key = bytearray([
        0x04, 0x84, 0x22, 0x42, 0xF6, 0x18, 0x2B, 0xA1, 0xC1, 0x13,
        0x8D, 0x32, 0xB7, 0x7F, 0xB9, 0xF7, 0xF3, 0x7B, 0x70, 0x03,
        0x4B, 0x9F, 0x04, 0x44, 0x3A, 0x5B, 0xEA, 0x3C, 0x18, 0x8B,
        0xEA, 0xDB, 0x36, 0x49, 0x0A, 0x7E, 0x95, 0xF9, 0x1A, 0x4C,
        0x16, 0x2A, 0xCF, 0xC3, 0x40, 0x1C, 0x3A, 0x4F, 0x4E, 0x5A,
        0x59, 0x25, 0x1D, 0x45, 0x24, 0x3A, 0xC8, 0x54, 0x4A, 0x66,
        0x5C, 0xB9, 0x51, 0x42, 0x2F])

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Prerequisites"),
            TestStep("Step2: Send select command if signaling bitmap is set"),
            TestStep("Step3: Receive Envelope"),
            TestStep("Step4: Send Get Response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        cert = self.th_reader_certificate()

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            reader_cert=cert,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
        )


    @log_errors
    async def execute(self) -> None:
        # Prerequisites
        # Display pop-up to put the User Device UT on the TH
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
            )
        )

        try:
            await self.reader.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        try:
            await self.reader.expedited_transaction_standard(
                AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        # Test step 2
        try:
            if self.reader.session.step_up_aid_select_required():
                logger.info("Step-up AID SELECT command required")
                await self.reader.handle_select(STEPUP_PHASE_AID)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 3 and 4
        try:
            response = await self.reader.handle_envelope(self.request)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        # Parse response
        logger.info(f"Cbor = {response}")
        device_response = DeviceResponse()
        if device_response.from_cbor(response):
            logger.info("Successfully parsed the CBOR to populate a Device Response.")
        else:
            self.mark_step_failure("Failed to parse the CBOR.")
            return

        # Validate response
        if not device_response.is_valid():
            self.mark_step_failure("Failed to validate device response.")
            return

        # Validate hash and signature
        for document in device_response.documents:
            if document.check_signature(self.issuer_private_key):
                self.mark_step_failure("Document signature is invalid.")
                return

        self.next_step()
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_NFC_STPUP_10 Cleanup")
        await self.reader.transaction_termination()
