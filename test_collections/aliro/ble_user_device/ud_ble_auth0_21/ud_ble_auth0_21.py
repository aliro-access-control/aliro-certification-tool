from binascii import hexlify
import time

from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair, PublicKey
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class UD_BLE_AUTH0_21(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-BLE-AUTH0-2.1",
        "version": "0.0.1",
        "title": "UD-BLE-AUTH0-2.1",
        "description": """Verify conformance of User Device UT in AUTH0 command.""",
    }

    reader_ePuBK = bytes.fromhex(
        "049696afe33de58b7d3253d1cba86d14147c16d455e8"
        "a27373b38d454af21b70e75e13ebc6d55743ba6a6ffc"
        "4ed37a55515a9346fdae311f60be30421fa6dc61c5"
    )
    reader_ePuBK_2 = bytes.fromhex(
        "04f39b4ca9ffdf7b6af338af3c7c7a7973794652a2354"
        "a966b5cc0fef88e9f3a9211930161aab3d9baf77a81898"
        "e768afcce6db853b170489db3c08fd168e159a4"
    )
    reader_ePrivK = bytes.fromhex(
        "3c0f74114cd2a021e8066efbaa31dbb97ef0054272192606fd96633a04f66214"
    )
    reader_ePrivK_2 = bytes.fromhex(
        "e20ca94fba4c29d65d20456029da9ab45921075cdaed72cd5d1dcc5e552023f8"
    )
    transaction_identifier = bytes.fromhex("4165A83667AD0AF5AB115247424822E0")
    transaction_identifier_2 = bytes.fromhex("3d4fa85d4bfcf30b61b804eb9b3ff7cc")

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
            TestStep("Step2: Transaction initiation (standard)"),
            TestStep("Step3: Send/Receive AUTH0 command/response"),
            TestStep("Step4: Send/Receive AUTH1 command/response"),
            TestStep("Step5: Send/Receive EXCHANGE command/response"),
            TestStep("Step6: Transaction initiation (fast)"),
            TestStep("Step7: Send/Receive AUTH0 command/response"),
            TestStep("Step8: Send/Receive Select command/response"),
            TestStep("Step9: Send/Receive Second AUTH0 command/response"),
        ]

    async def setup(self) -> None:
        logger.info("UD_BLE_AUTH0_21 setup")
        # load parameters from project config
        self.group_id = self.th_group_identifier()
        self.sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()


        # Initialize Aliro BLE Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.BLE_UWB,
            reader_group_identifier=self.group_id,
            reader_group_sub_identifier=self.sub_group_id,
            reader_key=key,
            transaction_identifier_list=[
                self.transaction_identifier,
                self.transaction_identifier_2,
            ],
            ephemeral_key_list=[
                KeyPair(self.reader_ePrivK, self.reader_ePuBK),
                KeyPair(self.reader_ePrivK_2, self.reader_ePuBK_2),
            ],
        )

    @log_errors
    async def execute(self) -> None:
        # Test step 1
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1\n"
                "and start user device scanning",
                options={"OK": 1},
            )
        )
        self.next_step()

        # Test step 2
        try:
            await self.reader.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test step 3
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 4
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        
        # Test step 5
        try:
            await self.reader.handle_exchange(False)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test step 6
        try:
            await self.reader.reader_status_access_protocol_completed(1, 0)
            time.sleep(0.1)
            await self.reader.transaction_termination()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Start user device scanning",
                options={"OK": 1},
            )
        )

        try:
            await self.reader.transaction_initiation()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 7
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.FAST,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
                
        # Check cryptogram
        if self.reader.session.signaling_bitmap == None:
            self.mark_step_failure("Signaling bitmap missing.")
            return
        if self.reader.session.credential_signed_timestamp == None:
            self.mark_step_failure("Credential signed timestamp missing.")
            return
        if self.reader.session.revocation_signed_timestamp == None:
            self.mark_step_failure("Revocation signed timestamp missing.")
            return

        first_signaling_bitmap = self.reader.session.signaling_bitmap
        first_credential_signed_timestamp = (
            self.reader.session.credential_signed_timestamp
        )
        first_revocation_signed_timestamp = (
            self.reader.session.revocation_signed_timestamp
        )
        self.next_step()
        
        # Test step 8
        try:
            await self.reader.handle_select(aid=EXPEDITED_PHASE_AID)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        
        # Test step 9
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.FAST,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        
        if (
            self.reader.session.signaling_bitmap == None
            or self.reader.session.signaling_bitmap == first_signaling_bitmap
        ):
            self.mark_step_failure(
                "Signaling bitmap missing or same as previous response."
            )
            return
        if (
            self.reader.session.credential_signed_timestamp == None
            or self.reader.session.credential_signed_timestamp
            == first_credential_signed_timestamp
        ):
            self.mark_step_failure(
                "Credential signed timestamp missing or same as previous response."
            )
            return
        if (
            self.reader.session.revocation_signed_timestamp == None
            or self.reader.session.revocation_signed_timestamp
            == first_revocation_signed_timestamp
        ):
            self.mark_step_failure(
                "Revocation signed timestamp missing or same as previous response."
            )
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_BLE_AUTH0_10 Cleanup")
        await self.reader.transaction_termination()
