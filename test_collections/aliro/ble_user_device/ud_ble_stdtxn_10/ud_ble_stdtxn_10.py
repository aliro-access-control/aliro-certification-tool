from aliro_actuator.access_protocol import TransportProtocol
from aliro_actuator.access_protocol.defines import EXPEDITED_PHASE_AID
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.transport_protocol import Mode
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase


class UD_BLE_STDTXN_10(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "UD-BLE-STDTXN-1.0",
        "version": "0.0.1",
        "title": "UD-BLE-STDTXN-1.0",
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

    BLE_UWB_VERSION = 0x0100

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Configure User Device to scan for BLE advertisements"),
            TestStep("Step2: Reader sends BLE packet: ADV_IND"),
            TestStep("Step3: User Device sends BLE packet: CONNECT_IND"),
            TestStep("Step4: User Device discovers services (GATT client)"),
            TestStep("Step5: Reader discovers services (GATT server)"),
            TestStep("Step6: Device sends BLE host Command"),
            TestStep("Step7: Reader sends BLE host response"),
            TestStep("Step8: Device BLE Host discovers GATT characteristics"),
            TestStep("Step9: Reader BLE Host discovers GATT characteristics"),
            TestStep("Step10: Device sends BLE host command: ATT_READ_BY_TYPE_REQ"),
            TestStep("Step11: Reader sends BLE host response: ATT_READ_BY_TYPE_RSP"),
            TestStep("Step12: Device sends BLE host command: ATT_WRITE_REQ"),
            TestStep("Step13: Reader sends BLE host response: ATT_WRITE_RSP"),
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
        )

    async def execute(self) -> None:
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )

        # Test step 1
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        # Done in setup
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Start user device scanning", options={"OK": 1}
            )
        )
        self.next_step()

        # Test step 2
        try:
            await self.reader.transport_protocol.initialization(
                Mode.READER,
                group_id,
                sub_group_id,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 3
        try:
            await self.reader.transport_protocol.driver.wait_for_connection()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 4
        self.next_step()

        # Test step 5
        self.next_step()

        # Test step 6
        self.next_step()

        # Test step 7
        self.next_step()

        # Test step 8
        self.next_step()

        # Test step 9
        self.next_step()

        # Test step 10
        self.next_step()

        # Test step 11
        self.next_step()

        # Test step 12
        self.next_step()

        # Test step 13
        try:
            ble_version = await self.reader.driver.wait_for_write()
            logger.info(
                "Checking ble version requested by User Device: 0x{:04x}".format(
                    ble_version
                )
            )
            if ble_version != self.BLE_UWB_VERSION:
                self.mark_step_failure(
                    "Invalid AC BLE UWB Protocol Version: 0x{:04x}, expected 0x{:04x}".format(
                        ble_version, self.BLE_UWB_VERSION
                    )
                )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("UD_BLE_STDTXN_10 Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
