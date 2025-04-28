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
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class BLEUWB_UD_RANGING_SUSPEND(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_UD_RANGING_SUSPEND",
        "version": "0.0.1",
        "title": "BLEUWB_UD_RANGING_SUSPEND",
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
            TestStep("Step0: Prerequisites"),
            TestStep("Step1: User Device sends AP message: Timesync"),
            TestStep("Step2: User Device sends AP message: Initiate Ranging"),
            TestStep("Step3: Reader sends AP message: RSS-M1"),
            TestStep("Step4: User Device sends AP message: RSS-M2"),
            TestStep("Step5: Reader sends AP message: RSS-M3"),
            TestStep("Step6: User Device sends AP message: RSS-M4"),
            TestStep("Step7: Reader acquires UWB ranging result"),
            TestStep("Step8: Reader sends Ranging Session Suspend Request"),
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

        # Test step 0: Prerequisites
        try:
            await self.reader.transaction_initiation()
            await self.reader.expedited_transaction_standard(
                authentication_policy=AuthenticationPolicy.USER_DEVICE_SECURE_ACTION
            )
            await self.reader.reader_status_access_protocol_completed(
                UnsolicitedReaderStatusReporting_Values.SEND_TO_EACH_CONNECTED,
                ReaderStatusInformation_Values.SECURED,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 1: User Device sends AP message: Timesync
        try:
            message = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            self.reader.handle_timesync(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 2: User Device sends AP message: Initiate Ranging
        # Test step 3: Reader sends AP message: RSS-M1
        try:
            message = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            await self.reader.handle_initiate_ranging(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 4: User Device sends AP message: RSS-M2
        # Test step 5: Reader sends AP message: RSS-M3
        try:
            message = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            await self.reader.handle_ranging_setup_m2(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 6: User Device sends AP message: RSS-M4
        try:
            message = await self.reader.wait_for_ble_message(
                self.reader.session.get_ble_encryption()
            )
            await self.reader.handle_ranging_setup_m4(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 7: Reader acquires UWB ranging result
        try:
            await self.reader.transport_protocol.start_ranging()
            range = await self.reader.transport_protocol.get_ranging_data()
            logger.info(f"Ranging value is: {range}")
            await self.reader.transport_protocol.stop_ranging()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        # Print UWB configuration
        try:
            uwb_configuration = (
                await self.reader.transport_protocol.get_uwb_configuration()
            )
            self.print_uwb_configuration(uwb_configuration)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 8: Reader sends Ranging Session Suspend Request
        try:
            await self.reader.send_ranging_session_suspend_request()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("BLEUWB_UD_RANGING_SUSPEND Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
