from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    INS,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidCommandError,
)
from aliro_actuator.access_protocol.user_device import UserDevice, UserSessionState
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.access_doc.mdl.request import DeviceRequest
from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class RD_NFC_ENVELOPE_10(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-ENVELOPE-1.0",
        "version": "0.0.1",
        "title": "RD-NFC-ENVELOPE-1.0",
        "description": """Verify conformance of Reader UT in ENVELOPE command.""",
    }

    endpoint_ePuBK = bytes.fromhex(
        "045d75ab60136a2c54ff27b799ee157f3f3329435c0d"
        "f608de904c920ac29f72bd4274c2edc810a93e240bf5"
        "d6394a92c9766b690b2bf5128ae70d6e29257ea786"
    )  # from Test Vector
    endpoint_ePrivK = bytes.fromhex(
        "70637ee9b40cee568567c69589276888edca7128bb13fb531f9c4f502d8cc65e"
    )  # from Test Vector

    device_response = bytes.fromhex(
        "A3613163312E30613282A2613567616C69726F2D616131A26131A167616C6"
        "9726F2D6181D818590132A461310161325011A3644571F7E4AD0C967C13B5"
        "7F6EFF613366666C6F6F72316134A6000101481234567890ABCDEF0282A30"
        "00301050202A200183F01050383A400C11A66C8682001C11A673F0F20024B"
        "00000E10000000150203000301A400C11A66C8682101C11A673F0F21024B0"
        "0001C200000006A0201000300A400C11A66C8682201C11A673F0F22024B00"
        "000708000000100402FF03010482187B1901C806A11A00FA1466828401010"
        "1A300815013AC8FF518435D4128C29D7B2741FBE501584104842B58578AEA"
        "55B293C68A40D39889008EF060DB2C76C5E643C7945CA143584DA1A53843E"
        "258CDEBB1ED23CCE4375D646486C5CF1AA051193AC20954D58EEF790281A2"
        "0048DB8C47BD724B6CD701501F8FD22CF28062853A5B402D62B0AD8F84010"
        "201A400181E01010202030261328443A10126A10448C61187E0F2F3503E58"
        "ECD81858E8A7613163312E306132675348412D3235366133A167616C69726"
        "F2D61A1015820CC20E3FEB91090C9ECE095ACFB50846901340ECD428DE345"
        "7553DDBD5ED6D2506134A16131A401022001215820ED1C8B8EB7E44C2842D"
        "B98730717C75CC94C96AB9AE60F079879E756980B4003225820B38FB44920"
        "3F7237CB9F81077B8AC49C75C8115ED408312222EAB61E18FECA176135676"
        "16C69726F2D616136A36131C074323032342D30382D32335431303A34343A"
        "34375A6132C074323032342D30382D32335431303A34343A34375A6133C07"
        "4323032342D30392D30365431303A34343A34375A6137F458404BCDA1C8E4"
        "0709885949D982DB532F7A061B541487AEC09D458ECADAA15ABC720C6E6DE"
        "4DFD53A8578932094E271F2F5D33477E95CED33F6D9A86EEC693E9C81A261"
        "3567616C69726F2D726131A26131A167616C69726F2D7281D818590111A46"
        "13101613250FC39E9E18272ED8BA1BDC491BAEFC821613366666C6F6F7232"
        "6134A5000101000282A30058200102030405060708090A0B0C0D0E0F10111"
        "2131415161718191A1B1C1D1E1F2001481234567890ABCDEF02C11A673F0F"
        "1FA30058206465666768696A6B6C6D6E6F707172737475767778797A7B7C7"
        "D7E7F808182830150ABACADAEAFB0B1B2B3B4B5B6B7B8B9BA02C11A66D1A2"
        "9F0382A2005820C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDED"
        "FE0E1E2E3E4E5E6E70150CBCCCDCECFD0D1D2D3D4D5D6D7D8D9DAA2005820"
        "28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454"
        "647014630313233343504A11A00ABCDEF818319014109A200010102613284"
        "43A10126A10448C61187E0F2F3503E58ECD81858E8A7613163312E3061326"
        "75348412D3235366133A167616C69726F2D72A101582072E21C4D7F4FEE8B"
        "EC578015E5AE5DE50999DDD560B182610C268ECDF12F9FA06134A16131A40"
        "1022001215820ED1C8B8EB7E44C2842DB98730717C75CC94C96AB9AE60F07"
        "9879E756980B4003225820B38FB449203F7237CB9F81077B8AC49C75C8115"
        "ED408312222EAB61E18FECA17613567616C69726F2D726136A36131C07432"
        "3032342D30382D32335431303A34343A34375A6132C074323032342D30382"
        "D32335431303A34343A34375A6133C074323032342D30392D30365431303A"
        "34343A34375A6137F458406CF4DCDA41ABC344AB19DD957F05E0A7BB16740"
        "2E79ED0ADD2865FD41EE5DAE88BD187CFCFD927F7DFC5A8FD0AB1E37A6A5C"
        "14B9658C358D5F5F1DD96C7F22DC613300"
    )

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )

    def create_test_steps(self) -> None:
        self.test_steps = [
            TestStep("Step1: Prerequisites"),
            TestStep("Step2: Send SELECT id signaling bitmap is set"),
            TestStep("Step2: Send Envelope command"),
            TestStep("Step3: Receive get response"),
        ]

    async def setup(self) -> None:
        logger.info("This is a test case setup")
        access_credential = self.reader_access_credential()
        self.userdevice = UserDevice(
            transport_protocol=TransportProtocol.NFC,
            access_credentials=[access_credential],
            mailbox=0x20,
            ephemeral_key_list=[KeyPair(self.endpoint_ePrivK, self.endpoint_ePuBK)],
            access_document=self.device_response,
        )

    @log_errors
    async def execute(self) -> None:
        # Prerequisites
        # Display pop-up to set the Reader Device Under Test in polling mode
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Set Reader Device Under Test in NFC polling mode",
                options={"OK": 1},
            )
        )

        # Display pop-up to put the Test Harness on the Reader device Under Test
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Bring Test Harness above Reader Device Under Test",
                options={"OK": 1},
            )
        )
        try:
            await self.userdevice.transaction_initiation()  # including select
        except (AccessProtocolError, InvalidCommandError) as error:
            self.mark_step_failure(str(error))
            return

        try:
            cmds_auth0 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        try:
            await self.userdevice.handle_auth0(cmds_auth0)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        if not self.userdevice.session.state_valid(UserSessionState.AUTH0_STD_DONE):
            self.mark_step_failure(
                "Userdevice is not in state auth0 standard done, either fast "
                "transaction was requested or handling auth0 failed"
            )

        try:
            cmds_auth1 = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return
        if cmds_auth1.expected_response != Auth1Response.CREDENTIAL_PUBLIC_KEY:
            self.mark_step_failure(
                "Access Credential key type request is not endpoint public key!"
            )
            return

        # Test step 2
        try:
            await self.userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 3,4 - reader sends envelope
        try:
            cmds_envelope = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
            return

        device_request = DeviceRequest()
        if not device_request.from_cbor(cmds_envelope.decrypted_payload):
            self.mark_step_failure("Failed to parse device request.")
            return

        if not device_request.is_valid():
            self.mark_step_failure("Failed to validate device request.")
            return

        try:
            await self.userdevice.handle_envelope(cmds_envelope)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("RD_NFC_STPUP_10 Cleanup")
        await self.userdevice.transaction_termination()
