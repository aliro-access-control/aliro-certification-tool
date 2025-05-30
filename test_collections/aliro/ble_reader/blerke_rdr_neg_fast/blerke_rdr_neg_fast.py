from binascii import hexlify

from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice, RkeAction
from aliro_actuator.transport_protocol.ble_message_format import (
    Notification_ID,
    OperationSourceInformation_Values,
    ReaderStatusInformation_Values,
    UnsolicitedReaderStatusReporting_Values,
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class BLERKE_RDR_NEG_FAST(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLERKE_RDR_NEG_FAST",
        "version": "0.0.1",
        "title": "BLERKE_RDR_NEG_FAST",
        "description": """Verify conformance of Reader in BLE discovery.""",
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
            TestStep("Step1: User Device sends AP Message: Initiate AP"),
            TestStep("Step2: Reader sends AP_RQ message: AUTH0 cmd"),
            TestStep("Step3: User Device sends AP_RS message: AUTH0 response"),
            TestStep("Step4: Reader sends AP_RQ message: AUTH1 cmd"),
            TestStep("Step5: User Device sends AP_RS message: AUTH1 response"),
            TestStep("Step6: Reader sends AP_RQ message: EXCHANGE command"),
            TestStep("Step7: Device sends AP_RS message: EXCHANGE response"),
            TestStep("Step8: Reader sends AP message: AP completed"),
            TestStep("Step9: Device sends RKE request message"),
            TestStep("Step10: Reader sends Reader Status Changed message"),
        ]

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
            enable_uwb=False,
        )

    @log_errors
    async def execute(self) -> None:
        # Done in setup
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in BLE advertising mode",
                options={"OK": 1},
            )
        )
            
        for _ in range(0,10):
            try:
                await self.userdevice.setup_connection()
                self.userdevice.start_new_session()
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return

       
            # Test step 1
            try:
                await self.userdevice.send_initiate_access_protocol_notification(rke=True)
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()

            # Test step 2
            try:
                cmds_auth0 = await self.userdevice.wait_for_command(
                    expected_command=INS.AUTH0
                )
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()

            # Test step 3
            try:
                await self.userdevice.handle_auth0(cmds_auth0)
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()

            # Test step 4
            try:
                cmds_auth1 = await self.userdevice.wait_for_command(
                    expected_command=INS.AUTH1
                )
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()

            # Test step 5
            try:
                await self.userdevice.handle_auth1(cmds_auth1)
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()

            # Test step 6
            try:
                cmds_exchange = await self.userdevice.wait_for_command(
                    expected_command=INS.EXCHANGE,
                )
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()

            # Test step 7
            try:
                await self.userdevice.handle_exchange(cmds_exchange)
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()
            
            # Test step 8
            try:
                message_ap_completed = await self.userdevice.wait_for_ble_message()

                self.userdevice.handle_reader_status_access_protocol_completed_message(
                    message_ap_completed
                )
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()
            
            # Test step 9
            try:
                await self.userdevice.send_rke_request(RkeAction.UNSECURE)
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
            self.next_step()
            
            # Test step 10
            try:
                status_changed = await self.userdevice.wait_for_ble_message()
                if status_changed.id == Notification_ID.READER_STATUS_CHANGED:
                    self.userdevice.handle_reader_status_changed_message(status_changed)
                    # If we receive Reader Status Changed then we end the test
                if status_changed.reader_status_information != ReaderStatusInformation_Values.UNSECURED:
                    self.mark_step_failure("Wrong reader status information")
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return

    async def cleanup(self) -> None:
        logger.info("BLERKE_RDR_NEG_FAST Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
