from aliro_actuator.access_protocol.apdu import Auth1Response
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

from ...support.aliro_test_case import AliroReaderTestCase, log_errors


class RD_NFC_STPUP_10(AliroReaderTestCase, UserPromptSupport):
    metadata = {
        "public_id": "RD-NFC-STPUP-1.0",
        "version": "0.0.1",
        "title": "RD-NFC-STPUP-1.0",
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

    access_document = bytes.fromhex(
        "A3613163312E30613281A2613567616C69726F2D616131A26131A167616C69726F2D6181D81859"
        "0131A4613101613250F1F4CD236A8B4B2D40C0C05FCD17644C61336562312E66326134A6000101"
        "481234567890ABCDEF0282A3000301050202A200183F01050383A400C11A66AB89CF01C11A6722"
        "30CF024B00000E10000000150203000301A400C11A66AB89D001C11A672230D0024B00001C2000"
        "00006A0201000300A400C11A66AB89D101C11A672230D1024B00000708000000100402FF030104"
        "82187B1901C806A11A00FA14668284010101A300815013AC8FF518435D4128C29D7B2741FBE501"
        "584104281F30EA16C1F1B2102B5C3F273F7AFE60A92D827019D3B876AD5CB164D811B3C49AAC1E"
        "F7B6FA4540E31924B031B491165A2708A4A650D1B76F10FF581B260F0281A20048DB8C47BD724B"
        "6CD70150C50D5BE962F62E79F293B06D20B586F184010201A400181E01010202030261328443A1"
        "0126A10448C61187E0F2F3503E58ECD81858E8A7613163312E306132675348412D3235366133A1"
        "67616C69726F2D61A1015820B8202454C322E0706BE9DD07EDF1153D4E55516CCE2B33E0434CD7"
        "B757B322E36134A16131A401022001215820ED1C8B8EB7E44C2842DB98730717C75CC94C96AB9A"
        "E60F079879E756980B4003225820B38FB449203F7237CB9F81077B8AC49C75C8115ED408312222"
        "EAB61E18FECA17613567616C69726F2D616136A36131C074323032342D30382D30315431333A31"
        "323A34365A6132C074323032342D30382D30315431333A31323A34365A6133C074323032342D30"
        "382D31355431333A31323A34365A6137F458408569F64F9FDE45954EAD051B825A3FAD1A9C8A16"
        "68D0CEB384E9D78DD50834096C68A801D9794CFBC2CC18C6A9774D71A574BC3FF88D626E68460A"
        "4A19F1EC94613300"
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
            access_document=self.access_document,
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
        try:
            await self.userdevice.handle_auth1(cmds_auth1)
        except AccessProtocolError as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 2,3 - reader sends envelope
        try:
            cmds_envelope = await self.userdevice.wait_for_command()
        except InvalidCommandError as error:
            self.mark_step_failure(str(error))
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
