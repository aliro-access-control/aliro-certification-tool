from aliro_actuator.access_protocol.apdu import (
    INS,
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice
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

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class BLEUWB_RDR_TIMEOUT_EXTENSION(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_TIMEOUT_EXTENSION",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_TIMEOUT_EXTENSION",
        "description": """Verify conformance of User Device UT in BLE discovery.""",
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
            TestStep("Step1: Establish L2CAP"),
            TestStep("Step2: Send Initiate AP Message ID"),
            TestStep("Step3: Wait for AUTH0 Command"),
            TestStep("Step4: Wait for 1 second"),
            TestStep("Step5: Send General error with Busy attribute"),
            TestStep("Step6: Send AUTH0 Response after 1 second"),
            TestStep("Step7: Handle AUTH1"),
            TestStep("Step8: Handle EXCHANGE"),
            TestStep("Step9: Handle AP Completed message"),
        ]

    def print_uwb_configuration(self, uwb_config: dict) -> None:
        logger.info("UWB Configuration is:")
        logger.info("-" * 50)
        for key, value in uwb_config.items():
            logger.info(f"{key:<12}: {value}")
        logger.info("-" * 50)

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        self.access_credential = self.reader_access_credential(add_issuer_public_key=True)
        group_resolving_key = self.reader_group_resolving_key()
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.BLE_UWB,
            access_credentials=[self.access_credential],
            mailbox=0x20,
            group_resolving_key=group_resolving_key,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
        )

    @log_errors
    async def execute(self) -> None:
        # Done in setup
        issuer_group_id = self.access_credential.reader_id_key_list[1][0]
        
        # Test step 1: Establish L2CAP
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        try:
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Set Reader Device Under Test in BLE advertising mode",
                    options={"OK": 1},
                )
            )
            await self.userdevice.setup_connection()
            self.userdevice.start_new_session()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 2: Send Initiate AP Message ID
        try:
            await self.userdevice.send_initiate_access_protocol_notification()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 3: Wait for AUTH0 Command
        try:
            cmds_auth0 = await self.userdevice.wait_for_command(
                expected_command=INS.AUTH0
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Test step 4: Wait for 1 second
        time.sleep(1)

        self.next_step()
        # Test step 5: Send General error with Busy attribute
        try:
            await self.userdevice.send_event(Event_AttributeID.BUSY, None)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)

        self.next_step()
        # Step6: Send AUTH0 Response after 1 second
        time.sleep(1)
        try:
            await self.userdevice.handle_auth0(cmds_auth0)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        
        self.next_step()
        # Step7: Handle AUTH1
        try:
            cmds_auth1 = await self.userdevice.wait_for_command(
                expected_command=INS.AUTH1
            )
            await self.userdevice.handle_auth1(cmds_auth1)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step8: Handle EXCHANGE
        try:
            cmds_exchange = await self.userdevice.wait_for_command(
                expected_command=INS.EXCHANGE
            )
            if cmds_exchange.ursk is None:
                self.mark_step_failure("Expected URSK tag in exchange command")
                return
            await self.userdevice.handle_exchange(cmds_exchange)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        self.next_step()
        # Step9: Handle AP Completed message
        try:
            cmds = await self.userdevice.wait_for_message()
            self.userdevice.handle_reader_status_access_protocol_completed_message(cmds)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        await self.userdevice.transaction_termination()

    async def cleanup(self) -> None:
        logger.info("BLEUWB_UD_RANGING_SUSPEND Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
