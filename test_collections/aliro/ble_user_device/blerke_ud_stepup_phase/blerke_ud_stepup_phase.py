from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    ReaderStatus,
    Transaction,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    STEPUP_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.access_protocol.reader import Reader, ReaderState
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
from test_collections.aliro.support.access_doc.mdl.response import DeviceResponse
from test_collections.aliro.support.access_doc.mdl.request.device_request_builder import DeviceRequestBuilder, RequestElement


class BLERKE_UD_STEPUP_PHASE(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLERKE_UD_STEPUP_PHASE",
        "version": "0.0.1",
        "title": "BLERKE_UD_STEPUP_PHASE",
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
            TestStep("Step1: STEPUP: Request Access Document"),
            TestStep("Step2: STEPUP:Exchange Routine "),
            TestStep("Step3: Reader sends AP message: AP completed"),
            TestStep("Step5: Reader handle rke request"),
            TestStep("Step4: Reader sends AP message: Status changed"),
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
        # Build the Device Request.
        self.issuer_public_key, self.element_id = self.th_access_document_data()
        self.request = DeviceRequestBuilder.build(
            [RequestElement(self.element_id, False)], [RequestElement(self.element_id, False)]
        ).to_cbor()
        logger.info(f"Generated Device Request: {self.request.hex()}")

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

        # Test step 1: STEPUP: Request Access Document
        try:
            response = await self.reader.handle_envelope(self.request)
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return

        # Parse response
        logger.info(f"Cbor = {response.hex()}")
        device_response = DeviceResponse()
        if device_response.from_cbor(response):
            logger.info("Successfully parsed the CBOR to populate a Device Response.")
        else:
            self.mark_step_failure("Failed to parse the CBOR.")
            return

        # Validate response
        if not device_response.is_valid():
            self.mark_step_failure("Failed to validate device response.")
            return

        # Validate hash and signature
        for document in device_response.documents:
            if not document.check_signature(
                    self.issuer_public_key.as_bytes(),
                    self.reader.session.credential_pubk.as_bytes()
            ):
                self.mark_step_failure("Document signature is invalid.")
                return
        self.next_step()

        # Test step 2: STEPUP:Exchange Routine
        try:
            await self.reader.handle_exchange(False, reader_state = ReaderState.STEPUP)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 3 - Reader sends AP message: AP completed
        try:
            await self.reader.reader_status_access_protocol_completed(1, 0)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 4 - Reader handle rke request
        try:
            await self.reader.handle_rke_request()
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        
        if self.reader.rke_action == 0:
            reader_status = ReaderStatusInformation_Values.SECURED
        else:
            reader_status = ReaderStatusInformation_Values.UNSECURED
        self.next_step()

        # Test step 5: Reader sends AP message: Status changed
        try:
            await self.reader.reader_status_status_changed(
                OperationSourceInformation_Values.UNSPECIFIED,
                reader_status,
            )
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return

    async def cleanup(self) -> None:
        logger.info("BLERKE_UD_STEPUP_PHASE Cleanup")
        try:
            await self.reader.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
