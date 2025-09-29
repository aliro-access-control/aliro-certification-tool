from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.hw_driver.murata_driver.errors import DeviceDisconnectedError, NoResponseError
from aliro_actuator.hw_driver.murata_driver.opcodes import (
    OpCodeGAP,
    OpGroup,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.transport_protocol import Mode
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.transport_protocol.ble_uwb import INVALID_VERSIONS, SUPPORTED_VERSIONS
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors


class BLEUWB_UD_NEG_FAILED_L2CAP(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLEUWB_UD_NEG_FAILED_L2CAP",
        "version": "0.0.1",
        "title": "BLEUWB_UD_NEG_FAILED_L2CAP",
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
            TestStep("Step1: Configure User Device to scan for BLE advertisements"),
            TestStep("Step2: Setup BLE connection with invalid BLE UWB Protocol Version in Reader Characteristic"),
            TestStep("Step3: L2CAP connection establishment failure"),
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

    @log_errors
    async def execute(self) -> None:
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Reset murata board by pressing switch SW1",
                options={"OK": 1},
            )
        )

        # Test step 1
        # Done in setup
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Start user device scanning", options={"OK": 1}
            )
        )
        self.next_step()

        # Test step 2
        try:
            logger.info("Setting up connection")
            await self.reader.transport_protocol.initialization(
                Mode.READER,
                reader_group_identifier=self.reader.reader_group_identifier,
                reader_group_sub_identifier=self.reader.reader_group_sub_identifier,
                group_resolving_key=self.reader.group_resolving_key,
                spsm=self.reader.spsm,
                timeout=self.reader.timeout,
                advertisement_version=self.reader.advertisement_version,
                enable_uwb=self.reader.enable_uwb,
                reader_supported_ble_uwb_versions=INVALID_VERSIONS
            )
            # Wait for GAP connection to be established
            await self.reader.transport_protocol.driver.wait_for_connection()
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 3
        try:
            # Set timeout on the reader before L2CAP Connection channel establishment
            self.reader.transport_protocol.driver.enable_timeout = True
            self.reader.transport_protocol.driver.timeout = 10
            self.reader.transport_protocol.ble_version, self.reader.transport_protocol.features = await self.reader.transport_protocol.driver.wait_for_write()
            logger.info(
                "Checking ble version requested by User Device: 0x{:4x}".format(
                    self.reader.transport_protocol.ble_version
                )
            )
            if self.reader.transport_protocol.ble_version in SUPPORTED_VERSIONS:
                logger.info("User Device requested a valid BLE UWB protocol version")
            if self.reader.transport_protocol.ble_version in INVALID_VERSIONS:
                logger.info("User Device requested an invalid BLE UWB protocol version as indicated by the Reader")
            await self.reader.transport_protocol.driver.setup_l2cap_connection_reader(self.reader.spsm)
        except (DeviceDisconnectedError, NoResponseError) as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            logger.info(error_str)
            logger.info("L2CAP connection establishment failed as expected, disconnect devices")
        else:
            self.mark_step_failure("Wrong BLE_UWB protocol version was accepted for L2CAP connection.")
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("BLEUWB_UD_NEG_FAILED_L2CAP Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
