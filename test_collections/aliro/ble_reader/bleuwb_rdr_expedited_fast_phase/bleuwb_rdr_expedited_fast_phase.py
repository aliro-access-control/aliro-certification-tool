from binascii import hexlify

from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.transport_protocol.ble_message_format import (
    Notification_ID,
    ReaderStatusInformation_Values,
    UWB_RangingService_ID,
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class BLEUWB_RDR_EXPEDITED_FAST_PHASE(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_EXPEDITED_FAST_PHASE",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_EXPEDITED_FAST_PHASE",
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
                "RD",
                "BLEUWB",
                "RD43",
                "RD11",
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: User Device sends AP Message: Initiate AP"),
            TestStep("Step2: Reader sends AP_RQ message: AUTH0 cmd"),
            TestStep("Step3: User Device sends AP_RS message: AUTH0 response"),
            TestStep("Step4: Optional: AP_RQ message: LOAD CERT"),
            TestStep("Step5: Conditional: AP_RS message: LOAD CERT"),
            TestStep("Step6: Reader sends AP_RQ message: AUTH1 cmd"),
            TestStep("Step7: User Device sends AP_RS message: AUTH1 response"),
            TestStep("Step8: Reader sends AP_RQ message: EXCHANGE command"),
            TestStep("Step9: Device sends AP_RS message: EXCHANGE response"),
            TestStep("Step10: Reader sends AP message: AP completed"),
            TestStep("Step11: User Device sends AP Message: Initiate AP"),
            TestStep("Step12: Reader sends AP_RQ message: AUTH0 cmd"),
            TestStep("Step13: User Device sends AP_RS message: AUTH0 response"),
            TestStep("Step14: Reader sends AP_RQ message: EXCHANGE cmd"),
            TestStep("Step15: User Device sends AP_RS message: EXCHANGE response"),
            TestStep("Step16: Reader sends AP message: AP completed"),
            TestStep("Step17: User Device sends AP message: Timesync"),
            TestStep("Step18: User Device sends AP message: Initiate Ranging"),
            TestStep("Step19: Reader sends AP message: RSS-M1"),
            TestStep("Step20: User Device sends AP message: RSS-M2"),
            TestStep("Step21: Reader sends AP message: RSS-M3"),
            TestStep("Step22: User Device sends AP message: RSS-M4"),
            TestStep("Step23: Reader acquires UWB ranging result"),
            TestStep("Step24: Reader sends AP message: Status changed"),
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
        prompt = "In case LOAD_CERT is used set correct group ID"
        prompt += "Set the reader_group_identifier of the reader device to: {}\n".format(hexlify(issuer_group_id))
        prompt += "to the Access Credential of the reader device\n"

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt=prompt,
                options={"OK": 1},
            )
        )

        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        try:
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Set Reader Device Under Test in BLE advertising mode, "
                    "and prepare for a standard transaction",
                    options={"OK": 1},
                )
            )
            await self.userdevice.setup_connection()
            self.userdevice.start_new_session()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        # Test step 1
        try:
            await self.userdevice.send_initiate_access_protocol_notification()
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
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )
        self.next_step()

        # Test step 4
        try:
            cmds_auth1 = await self.userdevice.wait_for_command(
                expected_command=[INS.AUTH1, INS.LOAD_CERT]
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 5
        if cmds_auth1.ins == INS.LOAD_CERT:
            try:
                await self.userdevice.handle_load_cert(cmds_auth1)
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
        self.next_step()

        # Test step 6
        if cmds_auth1.ins == INS.LOAD_CERT:
            try:
                cmds_auth1 = await self.userdevice.wait_for_command(
                    expected_command=INS.AUTH1
                )
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return
        self.next_step()

        # Test step 7
        try:
            await self.userdevice.handle_auth1(cmds_auth1)
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 8
        try:
            cmds_exchange = await self.userdevice.wait_for_command(
                expected_command=INS.EXCHANGE,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 9
        try:
            await self.userdevice.handle_exchange(cmds_exchange)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 10
        try:
            message_ap_completed = await self.userdevice.wait_for_ble_message()

            self.userdevice.handle_reader_status_access_protocol_completed_message(
                message_ap_completed
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        await self.userdevice.transaction_termination()
        self.next_step()

        # Test step 11
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in BLE advertising mode, "
                "and prepare for a fast transaction",
                options={"OK": 1},
            )
        )
        try:
            await self.userdevice.transaction_initiation()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 12
        try:
            cmds_auth0 = await self.userdevice.wait_for_command(
                expected_command=INS.AUTH0
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 13
        try:
            await self.userdevice.handle_auth0(cmds_auth0)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_FAST_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 fast done, either standard "
                "transaction was requested or handling auth0 failed"
            )
        self.next_step()

        # Test step 14
        try:
            cmds_exchange = await self.userdevice.wait_for_command(
                expected_command=INS.EXCHANGE
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 15
        try:
            await self.userdevice.handle_exchange(cmds_exchange)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        if cmds_exchange.ursk is None:
            self.mark_step_failure(
                "EXCHANGE command does not contain tag 0x98 (make URSK available)"
            )
        self.next_step()
        
        # Test step 16
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

        # Test step 17: User Device sends AP message: Timesync
        try:
            await self.userdevice.send_timesync()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 18: User Device sends AP message: Initiate Ranging
        try:
            await self.userdevice.send_initiate_ranging()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 19: Reader sends AP message: RSS-M1
        # Test step 20: User Device sends AP message: RSS-M2
        try:
            message = await self.userdevice.wait_for_ble_message(
                self.userdevice.session.get_ble_encryption()
            )
            await self.userdevice.handle_ranging_setup_m1(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 21: Reader sends AP message: RSS-M3
        # Test step 22: User Device sends AP message: RSS-M4
        try:
            message = await self.userdevice.wait_for_ble_message(
                self.userdevice.session.get_ble_encryption()
            )
            await self.userdevice.handle_ranging_setup_m3(message)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 23: Reader acquires UWB ranging result
        # only reader
        try:
            await self.userdevice.transport_protocol.start_ranging()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        # Print UWB configuration
        try:
            uwb_configuration = (
                await self.userdevice.transport_protocol.get_uwb_configuration()
            )
            self.print_uwb_configuration(uwb_configuration)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 24: Reader sends AP message: Status changed
        while True:
            try:
                message = await self.userdevice.wait_for_ble_message()
                if message.id == Notification_ID.READER_STATUS_CHANGED:
                    self.userdevice.handle_reader_status_changed_message(message)
                    # If we receive Reader Status Changed then we end the test
                    if message.reader_status_information not in [ReaderStatusInformation_Values.UNSECURED,
                                                                 ReaderStatusInformation_Values.JAMMED,
                                                                 ReaderStatusInformation_Values.STARTED_UNSECURE,
                                                                 ReaderStatusInformation_Values.UNKNOWN]:
                        self.mark_step_failure("Wrong reader status information")
                    break
                elif (
                    message.id == UWB_RangingService_ID.RANGING_SESSION_SUSPEND_REQUEST
                ):
                    await self.userdevice.handle_ranging_session_suspend_request(
                        message
                    )
                elif (
                    message.id == UWB_RangingService_ID.RANGING_SESSION_SUSPEND_RESPONSE
                ):
                    await self.userdevice.handle_ranging_session_suspend_response(
                        message
                    )
                elif message.id == UWB_RangingService_ID.RANGING_SESSION_RESUME_REQUEST:
                    await self.userdevice.handle_ranging_session_resume_request(message)
                elif (
                    message.id == UWB_RangingService_ID.RANGING_SESSION_RESUME_RESPONSE
                ):
                    await self.userdevice.handle_ranging_session_resume_response(
                        message
                    )
            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return

    async def cleanup(self) -> None:
        logger.info("BLEUWB_RDR_EXPEDITED_FAST_PHASE Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
