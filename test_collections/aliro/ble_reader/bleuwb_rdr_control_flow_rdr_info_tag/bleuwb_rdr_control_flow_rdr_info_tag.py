from aliro_actuator.access_protocol.apdu import Auth1Response, INS, StatusBytes, Command
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
    SessionError,
)
from aliro_actuator.access_protocol.encryption import (
    VerificationError,
)
from aliro_actuator.transport_protocol.errors import (
    NoDeviceConnectedError,
)
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from binascii import hexlify
from ...support.aliro_test_case import AliroReaderTestCase, log_errors
from aliro_actuator import Global

class BLEUWB_RDR_CONTROL_FLOW_RDR_INFO_TAG(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_RDR_CONTROL_FLOW_RDR_INFO_TAG",
        "version": "0.0.1",
        "title": "BLEUWB_RDR_CONTROL_FLOW_RDR_INFO_TAG",
        "description": """Verify conformance of Reader UT in AUTH1 command.""",
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
            TestStep("Step 0: Transaction Initiation & Send initiate access protocol notification"),  
            TestStep("Step 1: Execute AUTH0 routine by sending wrong value of tag in AUTH0 response."),
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
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in BLE advertising mode",
                options={"OK": 1},
            )
        )

        # Test step 0: Transaction Initiation & Send initiate access protocol notification
        try:
            await self.userdevice.transaction_initiation()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 1: Execute AUTH0 routine by sending wrong value of tag in AUTH0 response.
        try:
            while True:
                try:
                    if self.userdevice.session is None:
                        raise SessionError("starting session failed")
                    message = await self.userdevice.wait_for_message()
                except (InvalidCommandError, VerificationError):
                    await self.userdevice.failure_process(StatusBytes.COMMAND_NOT_COMPLIANT)
                    return
                except NoDeviceConnectedError:
                    return
                try:
                    if isinstance(message, Command):
                        if (
                            self.userdevice.mailbox_session.is_started()
                            and message.ins != INS.EXCHANGE
                        ):
                            await self.userdevice.failure_process(StatusBytes.COMMAND_NOT_ALLOWED)
                            raise AccessProtocolError(
                                "received non-EXCHANGE command while an atomic session was "
                                "open"
                            )
                        match message.ins:
                            case INS.SELECT:
                                await self.userdevice.handle_select(message)
                            case INS.AUTH0:
                                await self.userdevice.handle_auth0_with_wrong_tag(message)
                            case INS.AUTH1:
                                await self.userdevice.handle_auth1(message)
                            case INS.LOAD_CERT:
                                await self.userdevice.handle_load_cert(message)
                            case INS.CONTROL_FLOW:
                                await self.userdevice.handle_control_flow(message)
                            case INS.EXCHANGE:
                                await self.userdevice.handle_exchange(message)
                            case _:
                                raise NotImplementedError(
                                    "command: {} not implemented".format(message.ins)
                                )
                except AccessProtocolError as error:
                    Global.logger.error(
                        "restarting session because of error: {}".format(repr(error))
                    )
                    await self.userdevice.failure_process(StatusBytes.COMMAND_NOT_COMPLIANT)
                    return
                except NoDeviceConnectedError:
                    return
                
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
       
    async def cleanup(self) -> None:
        logger.info("BLEUWB_RDR_CONTROL_FLOW_RDR_INFO_TAG Cleanup")
        await self.userdevice.transaction_termination()
