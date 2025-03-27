from aliro_actuator.access_protocol.apdu import (
    Auth1Response,
    AuthenticationPolicy,
    Transaction,
    ReaderStatus,
)
from aliro_actuator.access_protocol.defines import (
    EXPEDITED_PHASE_AID,
    TransportProtocol,
)
from aliro_actuator.access_protocol.errors import (
    AccessProtocolError,
    InvalidResponseError,
)
from aliro_actuator.access_protocol.reader import Reader
from aliro_actuator.trust_framework.key import KeyPair
from app.test_engine.logger import test_engine_logger as logger
from app.test_engine.models import TestStep
from app.user_prompt_support import OptionsSelectPromptRequest, UserPromptSupport

from ...support.aliro_test_case import AliroUserDeviceTestCase, log_errors
import random
import sys

class NFC_UD_EXCHANGE_SET_REQUEST(AliroUserDeviceTestCase, UserPromptSupport):
    metadata = {
        "public_id": "NFC_UD_EXCHANGE_SET_REQUEST",
        "version": "0.0.1",
        "title": "NFC_UD_EXCHANGE_SET_REQUEST",
        "description": """Expedited Phase With EXCHANGE command sending multiple SET requests multiple times.""",
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
    number_of_random_requests = 5

    @classmethod
    def pics(cls) -> set[str]:
        return set(
            [
                "",  # PICS in preparation
            ]
        )
    
    def create_test_steps(self) -> None:

        self.test_steps = [
            TestStep("Step1: Initialization"),
            TestStep("Step2: Set to polling mode"),
            TestStep("Step3: Transaction initiation"), #include select command and response
            TestStep("Step4: Send/Receive AUTH0 command/response"),
            TestStep("Step5: Send/Receive AUTH1 command/response"),
            TestStep("Step6: Send EXCHANGE command multiple times with multiple SET requests with atomic session = TRUE and Receive EXCHANGE response"),
            TestStep("Step7: Send EXCHANGE command with atomic session = FALSE and random requests and Receive EXCHANGE response"),
            TestStep("Step8: Send EXCHANGE command to read data written to the mailbox AND Receive EXCHANGE response"),
            TestStep("Step9: Send/Receive EXCHANGE command/response with Tag 0x97"),
        ]
        
    async def setup(self) -> None:
        logger.info("This is a test case setup")
        # load parameters from project config
        group_id = self.th_group_identifier()
        sub_group_id = self.th_sub_group_identifier()
        key = self.th_reader_keypair()
        # Initialize Aliro NFC Reader
        self.reader = Reader(
            transport_protocol=TransportProtocol.NFC,
            reader_group_identifier=group_id,
            reader_group_sub_identifier=sub_group_id,
            reader_key=key,
            transaction_identifier_list=[self.transaction_identifier],
            ephemeral_key_list=[KeyPair(self.reader_ePrivK, self.reader_ePuBK)],
        )
        
    @log_errors
    async def execute(self) -> None:
        
        # Test step 1
        # Done in setup
        self.next_step()

        # Test step 2
        # Display pop-up to put the User Device UT on the TH
        await self.send_prompt_request(
            OptionsSelectPromptRequest(
                prompt="Tap User Device on the Test Harness NFC", options={"OK": 1}
            )
        )
        self.next_step()

        # Test step 3
        try:
            await self.reader.transaction_initiation()  # including SELECT command
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 4
        authentication_policy = random.randint(
            AuthenticationPolicy.USER_DEVICE, 
            AuthenticationPolicy.FORCE_USER_AUTHENTICATION
        )
        try:
            await self.reader.handle_auth0(
                transaction_type=Transaction.STANDARD,
                authentication_policy=AuthenticationPolicy(authentication_policy),
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

        # Test step 5
        try:
            await self.reader.handle_auth1(
                expected_response=Auth1Response.CREDENTIAL_PUBLIC_KEY
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        bitmap_1 = self.reader.session.signaling_bitmap[1]
        if not (bitmap_1 & (1 << 5) == (1 << 5)):
            self.mark_step_failure("Auth1 response indicates mailbox cannot be written")
            return
        self.next_step()
        
        # Pre work for Test step 6
        mailbox = {
            0x00: None,
            0x42: None,
            0x63: None,
            0x22: None,
        } # To store mailbox initial data at pre-defined offsets .

        values_to_write_at_offsets = {
            0x00: 11223344556677,
            0x42: 1622334455657,
            0x63: 112233445568,
            0x22: 44162233448597,
        } # Keys are the offsets, values are the values to be written at those offsets

        read_requests_sequence = []
        for k,v in values_to_write_at_offsets.items():
            read_requests_sequence.append((k,sys.getsizeof(v)))
        # read_request_sequences = [(0x00, 32), (0x42, 32), (0x63, 32), (0x22, 32)]

        mailbox_data_before_write = []
        try:
            # Reading the non-updated values of mailbox
            mailbox_data_before_write.extend(await self.reader.handle_exchange(
                False, read_requests = read_requests_sequence, reader_status=ReaderStatus.READER_STATE_UNSECURED
            ))
                
            idx = 0
            for k in mailbox.keys():
                mailbox[k] = mailbox_data_before_write[idx] # Storing the fetched non-updated values in mailbox at corresponding offsets
                idx += 1

            '''mailbox[0x00] = mailbox_data_before_write[0]
            mailbox[0x42] = mailbox_data_before_write[1]
            mailbox[0x63] = mailbox_data_before_write[2]
            mailbox[0x22] = mailbox_data_before_write[3]
            '''
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        # TODO: Read entire mailbox 

        #  Test step 6 
        set_requests_sequences = []
        for k,v in values_to_write_at_offsets.items():
            set_requests_sequences.append((k,sys.getsizeof(v),v))
        set_requests_sequences = [set_requests_sequences[i:i+2] for i in range(0, len(set_requests_sequences), 2)]
        
        # set_requests_sequences = [
        #     [(0x00, 32, 11223344556677), (0x42, 32, 1622334455657)], 
        #     [(0x63, 32, 112233445568), (0x22, 32, 44162233448597)]
        # ]
        # Each sequence is used to send multiple set requests in the exchange command one time 

        for set_requests_sequence in set_requests_sequences:
            try:
                await self.reader.handle_exchange(
                    True, set_requests=set_requests_sequence, reader_status=ReaderStatus.READER_STATE_UNSECURED
                )
            except (AccessProtocolError, InvalidResponseError) as error:
                self.mark_step_failure(str(error))
                return
        self.next_step()

        # Test step 7

        read_requests = []
        write_requests = []
        for i in range(self.number_of_random_requests):
            r = random.randint(0,100)
            offset = random.choice(values_to_write_at_offsets.keys())
            if r % 2:
                read_requests.append(tuple(offset, len(values_to_write_at_offsets[offset])))
            else:
                data = random.randbytes(len(values_to_write_at_offsets[offset]))
                write_requests.append(tuple(offset, data))
                # mailbox[offset] = data
        try:
            result = await self.reader.handle_exchange(
                False, read_requests=read_requests, write_requests=write_requests, reader_status=ReaderStatus.READER_STATE_UNSECURED
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        
        if len(read_requests) > 0:
            index = 0
            for request in read_requests:
                if result[index] != mailbox[request[0]]:
                    # Compare with original data
                    self.mark_step_failure("Original / non-updated data of mailbox is not returned.")
                    return
                index += 1

        self.next_step()

        # Test step 8
        mailbox_data_after_write = []
        try:
            mailbox_data_after_write.extend(await self.reader.handle_exchange(
                False, read_requests = read_requests_sequence, reader_status=ReaderStatus.READER_STATE_UNSECURED
            ))
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
            
        idx = 0
        for request_sequence in read_requests_sequence:
            if mailbox_data_after_write[idx] != values_to_write_at_offsets[request_sequence[0]]:
                self.mark_step_failure("Data is not written in to mail box")
                return
            idx += 1
        self.next_step()

        # Test step 9
        try:
            await self.reader.handle_exchange(
                False, reader_status=ReaderStatus.READER_STATE_UNSECURED
            )
        except (AccessProtocolError, InvalidResponseError) as error:
            self.mark_step_failure(str(error))
            return
        self.next_step()

    async def cleanup(self) -> None:
        logger.info("NFC_UD_EXCHANGE_SET_REQUEST Cleanup")
        await self.reader.transaction_termination()
