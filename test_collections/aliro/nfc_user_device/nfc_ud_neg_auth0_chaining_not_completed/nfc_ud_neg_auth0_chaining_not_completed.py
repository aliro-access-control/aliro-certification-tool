
from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
    ReaderStatus,
    S2,
    INS,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    Auth0,
    Auth1,
    PROTOCOL_VERSION,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
    InvalidStatusError,
)
from aliro_actuator.access_protocol.tlv import TLV
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from aliro_actuator.access_protocol.authentication import create_reader_authentication

from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors

import os

class NFC_UD_NEG_AUTH0_CHAINING_NOT_COMPLETED(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_NEG_AUTH0_CHAINING_NOT_COMPLETED",
        "version": "0.0.1",
        "title": "NFC_UD_NEG_AUTH0_CHAINING_NOT_COMPLETED",
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

    dummy_credential_ephemeral_public_key = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
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
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set to polling mode"),
            TestStep("Step3: Set the User Device UT"),
            TestStep("Step4: Send/Receive Select command/response"),
            TestStep("Step5: Send/Receive AUTH0 command/response"),
            TestStep("Step6: Send/Receive AUTH1 command/response"),
            TestStep("Step7: Send/Receive CONTROL FLOW command/response"),
        ]

    async def setup(self) -> None:
        logger.info("NFC_UD_NEG_AUTH0_CHAINING_NOT_COMPLETED setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        protocol_version = PROTOCOL_VERSION

        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
            vendor_extension=os.urandom(100),
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
        self.next_step()

        # Test step 5
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
            le=0x00,
            max_data_len=30,
        )
        try:
            # do not send second block of the chain
            await self.reader.apdu.handle_chaining_send_command(
                "AUTH0", command, self.reader.transport_protocol, skip_command=1,
            )
        except (AccessProtocolError, InvalidResponseError, InvalidStatusError) as error:
            # error expected
            pass
        else:
            # success when it should not have
            self.mark_step_failure("Auth0 success when it should not have.")
            return

        self.next_step()
        
        # Test step 6
        try:
            # prepare context to generate properly formatted Auth1 (with dummy user-device ephemeral public key since we're not receiving an Auth0 response)
            command_parameters = Auth1Response.CREDENTIAL_PUBLIC_KEY
            data = create_reader_authentication(
                self.reader.reader_identifier,
                PublicKey(self.dummy_credential_ephemeral_public_key),
                self.reader.session.get_reader_epubkey(),
                self.reader.session.transaction_identifier,
            )
            reader_sig = self.reader.reader_key.sign(data.to_bytes())

            data_fields: list[tuple[int, bytes | list]] = [
                (Auth1.COMMAND_TAG, command_parameters.to_bytes(1, "big")),
                (Auth1.READER_SIG_TAG, reader_sig),
            ]

            data = TLV(data_fields)
            command = self.reader.apdu.create_command(
                cla=0x80,
                ins=INS.AUTH1,
                p1=0x00,
                p2=0x00,
                data=bytes(data.to_bytes()),
                le=0x00,
            )
            response = await self.reader.apdu.handle_chaining_send_command(
                "AUTH1", command, self.reader.transport_protocol
            )
        except InvalidStatusError as error:
            logger.info(
                "Received error status (as expected), status received: 0x{:04x}".format(
                    error.status
                )
            )
        else:
            self.mark_step_failure("No error status returned")
            return
        self.next_step()

        # Test step 7
        try:
            await self.reader.handle_control_flow(S2.NONE)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_NEG_AUTH0_CHAINING_NOT_COMPLETED Cleanup")
        await self.reader.transaction_termination()


