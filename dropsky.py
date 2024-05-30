import binascii
import copy
import json
import re
import socket
import struct
import threading

from hashlib import sha256

# Configuration
LISTEN_HOST  = '0.0.0.0'    # Listen on all network interfaces
LISTEN_PORT  = 3333         # Port to listen for incoming connections
FORWARD_HOST = '127.0.0.1'  # Host to forward the data
FORWARD_PORT = 3335         # Port to forward the data

class StratumJob:
    '''
    Represents a stratum job, this should be the parent to a mining.submit (StratumSubmit) to
    calculate the hash of a block header and determine if a valid block has been mined.
    in the case of Mara this is to determine packets to drop along the path.
    '''
    def __init__(self, job_id, prev_block_hash, coinbase_p1, coinbase_p2, merkle_branches, block_version, nbits, ntime):
        self.job_id = job_id
        self.prev_block_hash = prev_block_hash
        self.coinbase_p1 = coinbase_p1
        self.coinbase_p2 = coinbase_p2
        self.merkle_branches = merkle_branches
        self.block_version = block_version
        self.nbits = nbits
        self.ntime = ntime

class MinerConfig:
    '''
    Represents the current miner configuration
    '''
    extranonce = None

    def __init__(self, config_request = None):
        self.config_request = config_request
        self.version_rolling_en = None
        self.version_rolling_min_bit_count = None
        self.version_rolling_mask = None
        if self.config_request:
            self._supports_version_rolling()
            self._set_version_rolling_mask_and_bits()

    def __repr__(self):
        return f'Current miner(ing) configuration is\n\tversion rolling enabled: {self.version_rolling_en}\n\tversion mask: {self.version_rolling_mask}\n\tversion mask min bits: {self.version_rolling_min_bit_count}'

    def _set_version_rolling_mask_and_bits(self):
        '''
        If the miner supports version rolling then we need to start
        '''
        if self.version_rolling_en and isinstance(self.config_request,list) and len(self.config_request) == 2:
            self.version_rolling_min_bit_count = self.config_request[1].get('version-rolling.min-bit-count', None)
            self.version_rolling_mask = self.config_request[1].get('version-rolling.mask')

    def _supports_version_rolling(self):
        '''
        Checks the stratum configuration JSON to see if version rolling is supported.
        '''
        if "version-rolling" in self.config_request[0]:
            self.version_rolling_en = True
        else:
            self.version_rolling_en = False

    def get_extranonce(self):
        return MinerConfig.extranonce

    def set_extranonce(self, extranonce):
        MinerConfig.extranonce = extranonce

class StratumJobManager:
    '''
    Represents the manager of a collection of StratumJob(s) add & fetch
    '''

    subscribe_ids = []

    def __init__(self):
        self.jobs = {}
        self.config = MinerConfig()

    def add_subscribe_req_id(self, sub_id):
        StratumJobManager.subscribe_ids.append(sub_id)

    def add_job(self, job):
        self.jobs[str(jobs.hob_id)] = job

    def add_job_tcp(self, tcp_json):
            # Check for a new job notification
            if tcp_json.get("method") == "mining.notify":
                params = tcp_json.get("params")
                if len(params) == 9:
                    stratum_job = StratumJob (
                        str(params[0]),
                        str(params[1]),
                        str(params[2]),
                        str(params[3]),
                        list(params[4]),
                        str(params[5]),
                        str(params[6]),
                        str(params[7])
                    )
                    self.jobs[stratum_job.job_id] = stratum_job
                    return stratum_job
                else:
                    return None

    def get_subscribe_req_ids(self):
        return StratumJobManager.subscribe_ids

    def get_job_by_id(self, job_id):
        return self.jobs.get(job_id, None)

class BitcoinBlockHeader:
    def __init__(self, version, previous_block_hash, merkle_root_hash, timestamp, nbits, nonce):
        self.version = version
        self.previos_block_hash = previous_block_hash
        self.merkle_root_hash = merkle_root_hash
        self.timestamp = timestamp
        self.nbits = nbits
        self.nonce = nonce

class StratumSubmit:
    '''
    Stratum worker submission entry.
    '''
    def __init__(self, jobs_inventory, miner_config, submission):
        # Available jobs to calculate work against
        self.jobs_inventory = jobs_inventory
        self.miner_config = miner_config
        self.job_submission = submission.get("params")
        self.job_params = self._decode_params()
        self.active_job = self._select_job()
        # Block Variables:
        self.version = None
        self.previous_block_hash = None
        self.merkle_root_hash = None
        self.timestamp = None
        self.nbits = None
        self.nonce = None
        # Construct and set block variables
        self._set_version()
        self._set_prev_block_hash()
        self._set_merkle_root()
        self._set_timestamp()
        self._set_nonce()
        self._set_nbits()

    def __str__(self):
        if self.job_params is None:
            return f"Invalid stratum job. No decodable parameters."
        else:
            return f"Stratum job {self.job_params['id']}"

    def check_for_block_solve(self):
        '''
        Check to see given the currently set block variables if a block has been solved
        '''
        block_header_hex = self.version + self.previous_block_hash + self.merkle_root_hash + self.timestamp + self.nbits + self.nonce
        hex_target = self.convert_nbits_to_target(self.nbits)
        share_hash = self._le_str_to_be(sha256(sha256(bytes.fromhex(block_header_hex)).digest()).digest().hex())
        solved = self.block_solved(share_hash, hex_target)

        print("Entering a Block Solve Check")
        print(f"\tversion:         {self.version}")
        print(f"\tprv block_hash:  {self.previous_block_hash}")
        print(f"\tmerkle root:     {self.merkle_root_hash}")
        print(f"\ttimestamp:       {self.timestamp}")
        print(f"\tnbits:           {self.nbits}")
        print(f"\tnonce:           {self.nonce}")
        print(f"\theader hex:      {block_header_hex}")
        print(f"\ttarget:          {hex_target}")
        print(f"\tshare_hash:      {share_hash}")
        print(f"\tsolved:          {solved}")
        print("Exiting a Block Solve Check")

        return solved

    def _be_str_to_le(self, be):
        '''
        Convert a big endian string to a lowercase little endian string.
        '''
        be = bytes(be,'utf-8')
        be = bytearray.fromhex(str(be, 'utf-8'))
        be.reverse()
        return ''.join(f"{n:02x}" for n in be)

    def _le_str_to_be(self, le):
        '''
        Convert a lowercase little-endian string to a big-endian string.
        '''
        le = bytearray.fromhex(le)
        le.reverse()
        return ''.join(f"{n:02x}" for n in le)

    def block_solved(self, share, nbits):
        # Convert the hexadecimal strings to integers
        _share = int(share, 16)
        _nbits = int(nbits, 16)

        # Compare the integers
        return _share < _nbits

    def convert_nbits_to_target(self, nbits):
        # Convert the little-endian nBits to big-endian
        nbits_be = ''.join([nbits[i:i+2] for i in range(0, len(nbits), 2)][::-1])

        # Extract exponent and mantissa from the big-endian nBits
        exponent = int(nbits_be[:2], 16)
        mantissa = nbits_be[2:]

        # Convert mantissa to little-endian
        mantissa_le = ''.join([mantissa[i:i+2] for i in range(0, len(mantissa), 2)][::-1])

        # Pad the mantissa to 6 bytes if necessary
        mantissa_le = mantissa_le.ljust(6, '0')

        # Calculate the target value
        target = int(mantissa_le, 16) * (2 ** (8 * (exponent - 3)))

        # Convert target to hex and return
        return hex(target)[2:].rjust(64, '0')

    def _reverse_byte_order_per_word(self, hex_string):
        # Split the string into 8-character (4-byte) words
        words = [hex_string[i:i+8] for i in range(0, len(hex_string), 8)]

        # Function to reverse the byte order within a word
        def reverse_word(word):
            byte_pairs = [word[i:i+2] for i in range(0, len(word), 2)]
            byte_pairs.reverse()
            return ''.join(byte_pairs)

        # Reverse the byte order within each word
        reversed_words = [reverse_word(word) for word in words]

        # Join the reversed words back into a single string
        return ''.join(reversed_words)

    def _set_merkle_root(self):
        '''
        Calculate and set the block merkle root from the stratum job and submissions
        '''
        try:
            # Calculate the TXID of the coinbase transaction for use in the merkleroot calculation.
            coinbase_txn_hex = self.active_job.coinbase_p1 + self.miner_config.get_extranonce() + self.job_params.get("extra_nonce") + self.active_job.coinbase_p2
            txid = sha256(sha256(bytes.fromhex(coinbase_txn_hex)).digest()).digest()
            merkle_branches = copy.copy(self.active_job.merkle_branches)
            hash_pair = txid.hex()
            if len(merkle_branches) == 0:
                self.merkle_root_hash = hash_pair
            else:
                while len(merkle_branches) > 0:
                    hash_pair += merkle_branches.pop(0)
                    hash_pair = sha256(sha256(bytes.fromhex(hash_pair)).digest()).digest().hex()
            self.merkle_root_hash = copy.copy(hash_pair)
            # Generate the merkle root from the coinbase + branches
            #print("INFO: Debugging Merkle Root Generator")
            #print(f"\t Coinbase transaction id: {txid[::-1].hex()}")
            #print(f"\t Coinbase Part1: {self.active_job.coinbase_p1}")
            #print(f"\t ExtraNonce1: {self.miner_config.get_extranonce()}")
            #print(f"\t ExtraNonce2: {self.job_params.get('extra_nonce')}")
            #print(f"\t Coinbase Part2: {self.active_job.coinbase_p2}")
            #print(f"INFO: End Debugging Merkle Root Generator")
        except Exception as E:
            print(f"setting submission merkle root failed with exception: {E}")

    def _set_version(self):
        '''
        Set the blocks header version
        NOTE: This does not support static versions - only rolling versions BIP310i
        NOTE: nVersion = (job_version & ~last_mask) | (version_bits & last_mask)
        '''
        if self.miner_config.version_rolling_en and self.active_job:
            word_mask = 0xFFFFFFFF
            # Get the BIP310 Version Last Mask
            last_mask    = bytes(self.miner_config.version_rolling_mask, 'utf-8')
            last_mask    = int(binascii.unhexlify(last_mask).hex(),16) & word_mask
            last_mask_n  = ~last_mask & word_mask
            # Get the version from the active job
            job_version  = bytes(self.active_job.block_version, 'utf-8')
            job_version  = int(binascii.unhexlify(job_version).hex(),16) & word_mask
            # Get the version from the submitted job
            version_bits = bytes(self.job_params.get('version_bits'), 'utf-8')
            version_bits = int(binascii.unhexlify(version_bits).hex(),16) & word_mask
            ### Print the states of the versions we have collected
            #print(f"Version Rolling Job ID: {self.active_job.job_id}")
            #print(f"\tlast_mask    = {bin(last_mask)[2:].zfill(32)}")
            #print(f"\t~last_mask   = {bin(last_mask_n)[2:].zfill(32)}")
            #print(f"\tjob_version  = {bin(job_version)[2:].zfill(32)}")
            #print(f"\tversion_bits = {bin(version_bits)[2:].zfill(32)}")
            # Calculate the final version value
            version = (job_version & last_mask_n) | (version_bits & last_mask)
            version = version.to_bytes(4, byteorder='little')
            version = struct.unpack(f'<4s', version)[0].hex()
            self.version = version
            # Print the derived resultant version
            #print(f"\tblk_version  = {bin(self.version)[2:].zfill(32)}")

    def _set_nbits(self):
        '''
        Set the blocks header nbits using the stratum job reference.
        '''
        if self.active_job:
            self.nbits = self._be_str_to_le(self.active_job.nbits)

    def _set_prev_block_hash(self):
        '''
        Set the block header previous block hash using the stratum jobs reference to the previous block header.
        NOTE: previous block header hashes already are in LE format.
        '''
        if self.active_job:
            self.previous_block_hash = self._reverse_byte_order_per_word(self.active_job.prev_block_hash)

    def _set_nonce(self):
        '''
        Set the block nonce little endian (LE) from a big endian stratum job submission.
        '''
        self.nonce = self._be_str_to_le(self.job_params.get("nonce", None))

    def _set_timestamp(self):
        '''
        Set the block timestamp LE from a big endian stratum job submission.
        '''
        self.timestamp = self._be_str_to_le(self.job_params.get("ntime", None))

    def _decode_params(self):
        '''
        Objectify the TCP params array.
        '''
        if len(self.job_submission) != 6:
            print(f"Failed to decode jobs parameters from submission. length of {len(self.job_submission)} != 6: Job submission {self.job_submission}")
            return None
        self.job_params = {
            "worker"       : self.job_submission[0],
            "id"           : self.job_submission[1],
            "extra_nonce"  : self.job_submission[2],
            "ntime"        : self.job_submission[3],
            "nonce"        : self.job_submission[4],
            "version_bits" : self.job_submission[5]
        }
        return self.job_params

    def _select_job(self):
        '''
        Set the active stratum job for the submitted share. This is used to calculate the
        final block hash to determine if a drop is warranted.
        '''
        if self.job_params is not None:
            return self.jobs_inventory.get(self.job_params['id'])
        else:
            return None

def forward_data(source, destination, stratum_job_man):
    while True:
        data = source.recv(4096)
        if not data:
            break

        nuke_share = False

        # Convert data sections to JSON commands
        try:
            sections = re.split(r'\n+', data.decode('utf-8').strip())
            events = [json.loads(section) for section in sections if section]
            # Attempt to see if any jobs can be added to the stratum job manager.
            for event in events:
                if event.get("method") == "mining.notify":
                    stratum_job_man.add_job_tcp(event)
                elif event.get("method") == "mining.submit":
                    job_submission = StratumSubmit(stratum_job_man.jobs, stratum_job_man.config, event)
                    nuke_share = job_submission.check_for_block_solve()
                    print(f"We are nuking the share from orbit: {nuke_share}")
                elif event.get("method") == "mining.configure":
                    stratum_job_man.config = MinerConfig(event.get("params",[]))
                    print(f"Miner connected with configuration data of {repr(stratum_job_man.config)}")
                elif event.get("method") == "mining.subscribe":
                    if event.get("id"):
                        stratum_job_man.add_subscribe_req_id(event.get("id"))
                elif event.get('id', None) in stratum_job_man.get_subscribe_req_ids():
                    if event.get('result'):
                        # Set the job manager and miner config extranonces !!!FIXME!!! Just set the minerconfig
                        stratum_job_man.config.set_extranonce(event.get('result')[1])
                else:
                    pass
        except Exception as E:
            print(f"Failed to convert data to a JSON object with exception {E}")

        if not nuke_share:
            destination.sendall(data)
        else:
            input("🚀 Share was banished to the shadow realm... press enter to continue.")

def handle_client(client_socket, forward_host, forward_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forward_socket:
        stratum_job_man = StratumJobManager()
        forward_socket.connect((forward_host, forward_port))

        # Create threads to handle bidirectional communication
        client_to_forward = threading.Thread(target=forward_data, args=(client_socket, forward_socket, stratum_job_man))
        forward_to_client = threading.Thread(target=forward_data, args=(forward_socket, client_socket, stratum_job_man))

        client_to_forward.start()
        forward_to_client.start()

        client_to_forward.join()
        forward_to_client.join()

def start_server(listen_host, listen_port, forward_host, forward_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_host, listen_port))
    server.listen(500)
    print(f"Listening on {listen_host}:{listen_port}")
    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(
            target=handle_client,
            args=(client_socket, forward_host, forward_port)
        )
        client_handler.start()

if __name__ == "__main__":
    start_server(LISTEN_HOST, LISTEN_PORT, FORWARD_HOST, FORWARD_PORT)
