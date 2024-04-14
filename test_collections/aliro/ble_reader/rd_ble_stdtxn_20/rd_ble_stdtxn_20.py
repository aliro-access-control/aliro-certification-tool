from binascii import hexlify

from aliro_actuator.access_protocol import TransportProtocol
from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID
from aliro_actuator.access_protocol.user_device import UserDevice
from aliro_actuator.transport_protocol import Mode
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroReaderTestCase


class RD_BLE_STDTXN_20(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-BLE-STDTXN-2.0",
        "version": "0.0.1",
        "title": "RD-BLE-STDTXN-2.0",
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
            TestStep("Step4: Optional: AP_RQ message: LOAD CERT"),
            TestStep("Step5: Conditional: AP_RS message: LOAD CERT"),
            TestStep("Step6: Reader sends AP_RQ message: AUTH1 cmd"),
            TestStep("Step7: User Device sends AP_RS message: AUTH1 response"),
            TestStep("Step8: Reader sends AP_RQ message: EXCHANGE command"),
            TestStep("Step9: Device sends AP_RS message: EXCHANGE response"),
            TestStep("Step10: Optional: Reader sends AP_RQ message: ENVELOPE"),
            TestStep("Step11: Conditional: Device sends AP _RS message: GET RESPONSE"),
            TestStep("Step12: Reader sends AP message: AP completed"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")

    async def execute(self) -> None:
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )
        try:
            access_credential = self.reader_access_credential()
            group_resolving_key = self.reader_group_resolving_key()
            userdevice = UserDevice(
                transport_protocol=TransportProtocol.BLE_UWB,
                access_credentials=[access_credential],
                mailbox=0x20,
                group_resolving_key=group_resolving_key,
            )
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Set Reader Device Under Test in BLE advertising mode",
                    options={"OK": 1},
                )
            )
            await userdevice.transaction_initiation()  # up to RATS command/ ATS response
            userdevice.start_new_session(
                ephemeral_key=KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK),
            )
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return

        # Test step 1
        try:
            await userdevice.send_initiate_access_protocol_notification()
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 2
        try:
            cmds_auth0 = await userdevice.wait_for_command(expected_command=INS.AUTH0)
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 3
        try:
            await userdevice.handle_auth0(cmds_auth0)
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 4
        try:
            cmds_auth1 = await userdevice.wait_for_command(
                expected_command=[INS.AUTH1, INS.LOAD_CERT]
            )
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 5
        if cmds_auth1.ins == INS.LOAD_CERT:
            try:
                await userdevice.handle_load_cert(cmds_auth1)
            except Exception as error:
                "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error)
                return
        self.next_step()

        # Test step 6
        if cmds_auth1.ins == INS.LOAD_CERT:
            try:
                cmds_auth1 = await userdevice.wait_for_command(
                    expected_command=INS.AUTH1
                )
            except Exception as error:
                "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error)
                return
        self.next_step()

        # Test step 7
        try:
            await userdevice.handle_auth1(cmds_auth1)
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 8
        try:
            cmds_exchange = await userdevice.wait_for_command(
                expected_command=INS.EXCHANGE,
                encryption=userdevice.session.encryption,
            )
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 9
        try:
            await userdevice.handle_exchange(cmds_exchange)
        except Exception as error:
            "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error)
            return
        self.next_step()

        # Test step 10
        self.next_step()

        # Test step 11
        self.next_step()

        # Test step 12
        self.next_step()

        # Test step 13
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_BLE_STDTXN_20 Cleanup")
