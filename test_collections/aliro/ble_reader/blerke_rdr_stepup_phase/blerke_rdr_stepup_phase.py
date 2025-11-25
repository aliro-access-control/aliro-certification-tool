import datetime
from binascii import hexlify

from aliro_actuator.access_protocol.apdu import INS
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, RkeAction
from aliro_actuator.transport_protocol.ble_message_format import (
    Notification_ID,
    UWB_RangingService_ID,
    ReaderStatusInformation_Values,
)
from aliro_actuator.transport_protocol.errors import NoDeviceConnectedError
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.common import IssuerNamespaces, DocTypes
from ...support.aliro_test_case import AliroReaderTestCase, log_errors
from ...support.access_doc.mdl.request import DeviceRequest
from ...support.access_doc.mdl.response import DeviceResponse
from ...support.access_doc.aliro.access import AccessData
from ...support.access_doc.mdl.response.device_response_builder import DeviceResponseBuilder, ResponseElement

class BLERKE_RDR_STEPUP_PHASE(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "BLERKE_RDR_STEPUP_PHASE",
        "version": "0.0.1",
        "title": "BLERKE_RDR_STEPUP_PHASE",
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
                "BLERKE",
                "RD50",
                "RD23",
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step0: Prerequisites"),
            TestStep("Step1: STEPUP: envelope"),
            TestStep("Step2: Handle AP Completed"),
            TestStep("Step4: User Device sends RKE Request"),
            TestStep("Step5: Reader status changed"),
        ]

    def build_access_document(self, access_credential_pk: bytes) -> bytes:
        issuer_keypair, _, self.element_id = self.access_document_data()

        access_element = AccessData()
        access_element.version = 1

        x = DeviceResponseBuilder.build_doc(
            doc_type=DocTypes.ALIRO_ACCESS,
            namespace=IssuerNamespaces.ALIRO_ACCESS,
            data_elements=[ResponseElement(data_element_id=self.element_id, value=access_element)],
            issuer_private_key=issuer_keypair.get_private_key().as_bytes(),
            device_public_key=access_credential_pk,
            valid_from=datetime.datetime.now(datetime.timezone.utc),
            valid_until=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14)
        ).to_cbor()

        logger.info(f"Generated Access Document: {x.hex()}")
        return x

    def print_uwb_configuration(self, uwb_config: dict) -> None:
        logger.info("UWB Configuration is:")
        logger.info("-" * 50)
        for key, value in uwb_config.items():
            logger.info(f"{key:<12}: {value}")
        logger.info("-" * 50)

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        self.access_credential = self.reader_access_credential(add_issuer_public_key=True, use_random_ud_keypair=True)
        group_resolving_key = self.reader_group_resolving_key()
        access_doc = self.build_access_document(
            self.access_credential.get_access_credential_public_key().as_bytes()
        )
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.BLE_UWB,
            access_credentials=[self.access_credential],
            mailbox=None,
            group_resolving_key=group_resolving_key,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            access_document=access_doc,
            step_up_aid_required=True,
            enable_uwb=False,
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

        # Test step 0: Prerequisites
        try:
            await self.userdevice.send_initiate_access_protocol_notification(rke=True)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        try:
            cmds_auth0 = await self.userdevice.wait_for_command(
                expected_command=INS.AUTH0
            )
            await self.userdevice.handle_auth0(cmds_auth0)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
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
        while True:
            try:
                cmds_msg = await self.userdevice.wait_for_command()
                if cmds_msg.ins == INS.ENVELOPE:
                    break
                elif cmds_msg.ins == INS.EXCHANGE:
                    await self.userdevice.handle_exchange(cmds_msg)
                else:
                    self.mark_step_failure("Unexpected instruction: " + str(cmds_msg.ins))
                    return

            except Exception as error:
                error_str = "{}: {}".format(error.__class__.__name__, repr(error))
                self.mark_step_failure(error_str)
                return

        #   verify device request
        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_msg.decrypted_payload):
            self.mark_step_failure("Failed to parse device request.")
            return

        if not device_request.is_valid():
            self.mark_step_failure("Failed to validate device request.")
            return

        found_element = False
        for doc_type, elm_req in [y for x in device_request.doc_requests for y in
                                  x.items_request.namespaces.data.items()]:
            if doc_type != "aliro-a":
                continue
            if self.element_id in elm_req.keys():
                found_element = True

        if not found_element:
            self.mark_step_failure(f"Reader did not request Element ID {self.element_id}")
            return

        try:
            await self.userdevice.handle_envelope(cmds_msg)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 2 - STEPUP: exchange
        try:
            cmds_ap_completed = await self.userdevice.wait_for_message()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            self.userdevice.handle_reader_status_access_protocol_completed_message(cmds_ap_completed)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return

        self.next_step()

        # Test step 4: User Device sends AP message: Timesync
        try:
            await self.userdevice.send_rke_request(RkeAction.UNSECURE)
        except Exception as error:
            error_str = "{}: {}".format(error.__class__.__name__, repr(error))
            self.mark_step_failure(error_str)
            return
        self.next_step()

        # Test step 5: User Device sends AP message: Initiate Ranging
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
        logger.info("BLEUWB_RDR_STEPUP_PHASE Cleanup")
        try:
            await self.userdevice.transaction_termination()
        except NoDeviceConnectedError:
            # it is possible to end the test before any device is connected
            pass
