import logging
import multiprocessing as mp
import time

from crankycoin.models.block import Block
from crankycoin.models.transaction import Transaction
from crankycoin.models.enums import MessageType, TransactionType
from crankycoin.services.queue import Queue
from crankycoin import config, logger

class Miner(object):

    HOST = config['user']['ip']
    REWARD_ADDRESS = config['user']['public_key']
    MAX_TRANSACTIONS_PER_BLOCK = config['network']['max_transactions_per_block']
    miner_process = None

    def __init__(self, blockchain, mempool):
        mp.log_to_stderr()
        mp_logger = mp.get_logger()
        mp_logger.setLevel(logging.DEBUG)
        self.blockchain = blockchain
        self.mempool = mempool

    def start(self):
        logger.debug("mining process starting with reward address %s...", self.REWARD_ADDRESS)
        # run parallel
        self.miner_process = mp.Process(target=self.mine)
        self.miner_process.start()
        # run alone
        # self.mine()

    def shutdown(self):
        logger.debug("mining process with reward address %s shutting down...", self.REWARD_ADDRESS)
        self.miner_process.terminate()

    def mine(self):
        while True:
            block = self.mine_block()
            if not block:
                continue
            logger.info("Block {} found at height {} and nonce {}"
                        .format(block.block_header.hash, block.height, block.block_header.nonce))
            if self.blockchain.add_block(block):
                self.mempool.remove_unconfirmed_transactions(block.transactions[1:])
                message = {"host": self.HOST, "type": MessageType.BLOCK_HEADER.value, "data": block.block_header.to_json()}
                Queue.enqueue(message)
        return

    def mine_block(self):
        latest_block = self.blockchain.get_tallest_block_header()
        if latest_block is not None:
            latest_block_header = latest_block[0]
            latest_block_height = latest_block[2]
            new_block_height = latest_block_height + 1
            previous_hash = latest_block_header.hash
        else:
            new_block_height = 1
            previous_hash = ""

        transactions = self.mempool.get_unconfirmed_transactions_chunk(self.MAX_TRANSACTIONS_PER_BLOCK)
        print("[mine_block] len(transactions):{}".format(len(transactions)))
        if transactions is None or len(transactions) == 0:
            fees = 0
        else:
            fees = sum(t.fee for t in transactions)

        coinbase_prev_hash = "0" if new_block_height == 1 \
            else self.blockchain.get_coinbase_hash_by_block_hash(previous_hash)
        
        # coinbase
        coinbase = Transaction(
            "0",
            self.REWARD_ADDRESS,
            self.blockchain.get_reward(new_block_height) + fees,
            0,
            prev_hash=coinbase_prev_hash,
            tx_type=TransactionType.COINBASE.value,
            signature=""
        )

        print("[mine_block] new_block_height: {}".format(new_block_height))
        for t in range(len(transactions)):
            print("B: {} {}".format(t, transactions[t].prev_hash))
            transactions[t].prev_hash = transactions[t].tx_hash            
            print("A: {} {}".format(t, transactions[t].prev_hash))

        transactions.insert(0, coinbase)

        timestamp = int(time.time())
        i = 0
        block = Block(new_block_height, transactions, previous_hash, timestamp)

        print("[mine_block] new_block_height: {}".format(new_block_height))
        print("[mine_block] block.block_header.hash_difficulty: {}".format(block.block_header.hash_difficulty))
        acc = self.blockchain.calculate_hash_difficulty()
        while block.block_header.hash_difficulty < acc:
            print("[mine_block] self.blockchain.calculate_hash_difficulty(): {}".format(acc))
            latest_block = self.blockchain.get_tallest_block_header()
            if latest_block is not None:
                latest_block_header = latest_block[0]
                latest_block_height = latest_block[2]
                if latest_block_height >= new_block_height or latest_block_header.hash != previous_hash:
                    # Next block in sequence was mined by another node.  Stop mining current block.
                    return None
            i += 1
            block.block_header.nonce = i
            acc = self.blockchain.calculate_hash_difficulty()
            # print("[mine_block] block.block_header.nonce: {}".format(block.block_header.nonce))
        return block
