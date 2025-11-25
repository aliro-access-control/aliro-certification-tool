from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
    ReaderStatus,
    INS,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    Auth0,
    PROTOCOL_VERSION,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.access_protocol.vendor_extension import VendorExtension
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors

import os

class NFC_UD_AUTH0_RESPONSE_CHAINING(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_AUTH0_RESPONSE_CHAINING",
        "version": "0.0.1",
        "title": "NFC_UD_AUTH0_RESPONSE_CHAINING",
        "description": """Verify conformance of User Device UT in AUTH0 command.""",
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

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "UD",
                "NFC"
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set to polling mode"),
            TestStep("Step3: Set the User Device UT"),
            TestStep("Step4: Send/Receive Select command/response"),
            TestStep("Step5: Send/Receive AUTH0 command/response"),
            TestStep("Step6: Send/Receive AUTH1 command/response"),
            TestStep("Step7: Send/Receive EXCHANGE command/response"),
        ]

    async def setup(self) -> None:
        logger.info("NFC_UD_AUTH0_RESPONSE_CHAINING setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        protocol_version = PROTOCOL_VERSION
        vendor_ext = VendorExtension(b'\x00\x00\x01', TLV([(1, os.urandom(30))]))

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
            vendor_extension=vendor_ext.to_bytes(),
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        # Done in setup
        self.next_step()

        # Test step 2
        # Display pop-up to put the User Device UT on the TH
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
            )
        )
        self.next_step()

        # Test step 3
        await self.reader.setup_connection()  # up to RATS command/ ATS response
        self.reader.start_new_session()
        self.next_step()

        # Test step 4
        try:
            await self.reader.handle_select(aid=EXPEDITED_PHASE_AID)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.reader.apdu.reset_extended_length()
        self.next_step()

        # Test step 5
        self.reader.set_reader_ephemeral_key()

        data_tlv: list[tuple[int, bytes | list]] = [
            (Auth0.COMMAND_TAG, Transaction.STANDARD.to_bytes(1, "big")),
            (Auth0.AUTHENTICATION_POLICY_TAG, AuthenticationPolicy.USER_DEVICE.to_bytes(1, "big")),
            (Auth0.ETPV_TAG, PROTOCOL_VERSION.to_bytes(2, "big")),
            (Auth0.READER_EPUBK_TAG, self.reader_ePuBK),
            (Auth0.TRANSACTION_ID_TAG, self.transaction_identifier),
            (Auth0.READER_IDENTIFIER_TAG, self.reader.reader_identifier),
            (Auth0.VENDOR_SPECIFIC_TAG, self.reader.vendor_extension),
        ]
        data = TLV(data_tlv)

        command  = self.reader.apdu.create_command(
            cla=0x80,
            ins=INS.AUTH0,
            p1=0x00,
            p2=0x00,
            data=bytes(data.to_bytes()),
            le=0x3C, # Le set to 60
        )
        try:
            response = await self.reader.apdu.handle_chaining_send_command(
                "AUTH0", command, self.reader.transport_protocol
            )
            response = self.reader.apdu.parse_response(response, INS.AUTH0)

            logger.info("Saving Auth0 response data to session")
            credential_ephemeral_public_key = PublicKey(response.credential_epubk)
            self.reader.session.set_credential_ephemeral_key(credential_ephemeral_public_key)
            self.reader.session.set_flag(Transaction.STANDARD, AuthenticationPolicy.USER_DEVICE)
            self.reader.session.set_response_vendor_extension(response.vendor_specific_extensions)

        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        if response.response_chaining != True:
            self.mark_step_failure("Response is not chained.")
            return
        self.next_step()
        
        # Test step 6
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test step 7
        try:
            await self.reader.handle_exchange(
                False, reader_status=ReaderStatus.READER_STATE_UNSECURED
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_AUTH0_RESPONSE_CHAINING Cleanup")
        await self.reader.transaction_termination()