from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.transport_protocol.ble_message_format import (
    OperationSourceInformation_Values,
    ReaderStatusInformation_Values,
    UnsolicitedReaderStatusReporting_Values,
    Notification_ID,
    Event_AttributeID,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

import time
from binascii import hexlify

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class BLEUWB_UD_NEG_TIMEOUT_BEFORE_AUTH0(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_UD_NEG_TIMEOUT_BEFORE_AUTH0",
        "version": "0.0.1",
        "title": "BLEUWB_UD_NEG_TIMEOUT_BEFORE_AUTH0",
        "description": """Verify conformance of User Device UT in BLE discovery.""",
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
    group_resolving_key = 16 * bytes.fromhex("00")

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step0: Send Bluetooth LE advertisement"),
            TestStep("Step1: Establish L2CAP"),
            TestStep("Step2: Send Initiate AP Message ID"),
            TestStep("Step3: Wait for atleast 3 seconds"),
            TestStep("Step4: User device performs BLE connection teardown"),
        ]

    def print_uwb_configuration(self, uwb_config: dict) -> None:
        logger.info("UWB Configuration is:")
        logger.info("-" * 50)
        for key, value in uwb_config.items():
            logger.info(f"{key:<12}: {value}")
        logger.info("-" * 50)

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        spsm = self.th_spsm()
        group_resolving_key = self.th_group_resolving_key()
        self.reader = Reader(
            transport_protocol=TransportProtocol.BLE_UWB,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            spsm=spsm,
            group_resolving_key=group_resolving_key,
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
        )

    @log_errors
    async def execute(self) -> None:
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Start user device scanning", options={"OK": 1}
            )
        )

        # Step 0: Send Bluetooth LE advertisement
        try:
            await self.reader.setup_connection()
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        self.next_step()
        # Step1: Establish L2CAP
        try:
            self.reader.start_new_session()
            await self.reader.transport_protocol.driver.session_init(
                session_id=self.reader.session.transaction_identifier[-4:]
            )

        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step2: Send Initiate AP Message ID
        try:
            await self.reader.wait_for_initiate_access_protocol_notification()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step3: Wait for atleast 3 seconds
        time.sleep(3)

        self.next_step()
        # Step4: User device disconnects
        try:
            message_event = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            message_event.parse_payload(self.reader.session.get_ble_encryption())
        except NoDeviceConnectedError:
            logger.info("User Device disconnected as expected due to timeout waiting for Auth0")    
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        else:
            self.mark_step_failure(f"Unexpected BLE message received with header: {hexlify(message_event.header)}, id: {hexlify(message_event.id)}")
            return

    async def cleanup(self) -> None:
        logger.info("BLEUWB_UD_RANGING_SUSPEND Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
