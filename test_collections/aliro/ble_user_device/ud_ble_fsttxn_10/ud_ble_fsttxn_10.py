import time

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
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class UD_BLE_FSTTXN_10(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-BLE-FSTTXN-1.0",
        "version": "0.0.1",
        "title": "UD-BLE-FSTTXN-1.0",
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
            TestStep("Step13: User Device sends AP Message: Initiate AP"),
            TestStep("Step14: Reader sends AP_RQ message: AUTH0 cmd"),
            TestStep("Step15: User Device sends AP_RS message: AUTH0 response"),
            TestStep("Step16: Reader sends AP_RQ message: EXCHANGE cmd"),
            TestStep("Step17: User Device sends AP_RS message: EXCHANGE response"),
            TestStep("Step18: Reader sends AP message: AP completed"),
        ]

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
        try:
            await self.send_prompt_request(
                OptionsSelectPromptRequest(
                    prompt="Start user device scanning", options={"OK": 1}
                )
            )
            await self.reader.setup_connection()
            self.reader.start_new_session()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

        # Test step 1
        try:
            await self.reader.wait_for_initiate_access_protocol_notification()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 2 and step 3
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
        self.next_step()

        # Test step 4 and step 5
        # optional
        self.next_step()
        self.next_step()

        # Test step 6 and step 7
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 8 and step 9
        try:
            await self.reader.handle_exchange(False)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 10
        self.next_step()

        # Test step 11
        self.next_step()

        # Test step 12
        try:
            await self.reader.reader_status_access_protocol_completed(1, 0)
            time.sleep(0.1)
            await self.reader.transaction_termination()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 13
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

        # Test step 13 and step 14
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.FAST,
                authentication_policy=AuthenticationPolicy.USER_DEVICE,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 15 and step 16
        try:
            await self.reader.handle_exchange(False, ursk=b"")
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()
        self.next_step()

        # Test step 17
        try:
            await self.reader.reader_status_access_protocol_completed(1, 0)
            time.sleep(0.1)
            await self.reader.transaction_termination()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_BLE_FSTTXN_10 Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
