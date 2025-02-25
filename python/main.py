import os
import json
import hashlib
import struct
import time

DIFFICULTY_TARGET = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)
MEMPOOL_DIR = "mempool"

def read_transactions():
    transactions = []
    for file in sorted(os.listdir(MEMPOOL_DIR)):
        if file.endswith(".json"):
            with open(os.path.join(MEMPOOL_DIR, file), "r") as f:
                transactions.append(json.load(f))
    return transactions

def compute_txid(transaction):
    return hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()

def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def create_coinbase_tx():
    version = struct.pack("<I", 1)
    in_count = b"\x01"
    prev_tx_hash = b"\x00" * 32
    prev_tx_index = struct.pack("<I", 0xffffffff)
    coinbase_script = b"coinbase"
    coinbase_script_len = bytes([len(coinbase_script)])
    sequence = struct.pack("<I", 0xffffffff)
    tx_in = prev_tx_hash + prev_tx_index + coinbase_script_len + coinbase_script + sequence

    out_count = b"\x02"
    value1 = struct.pack("<Q", 5000000000)
    script1 = b"\x51"
    script1_len = bytes([len(script1)])
    tx_out1 = value1 + script1_len + script1

    value2 = struct.pack("<Q", 0)
    witness_commitment_data = b"\xaa\x21\xa9\xed" + (b"\x00" * 32)
    script2 = b"\x6a" + bytes([len(witness_commitment_data)]) + witness_commitment_data
    script2_len = bytes([len(script2)])
    tx_out2 = value2 + script2_len + script2

    locktime = struct.pack("<I", 0)
    non_witness = version + in_count + tx_in + out_count + tx_out1 + tx_out2 + locktime
    coinbase_txid = double_sha256(non_witness)[::-1].hex()

    witness = b"\x01" + b"\x00"
    marker_flag = b"\x00\x01"
    full_tx = version + marker_flag + in_count + tx_in + out_count + tx_out1 + tx_out2 + witness + locktime
    return full_tx.hex(), coinbase_txid

def simple_merkle_root(txids):
    if not txids:
        return "0" * 64
    txids_local = txids[:]
    while len(txids_local) > 1:
        if len(txids_local) % 2 == 1:
            txids_local.append(txids_local[-1])
        new_txids = []
        for i in range(0, len(txids_local), 2):
            new_txids.append(hashlib.sha256((txids_local[i] + txids_local[i+1]).encode()).hexdigest())
        txids_local = new_txids
    return txids_local[0]

def mine_block(previous_block_hash, merkle_root, timestamp):
    version = struct.pack("<I", 4)
    prev_block_le = bytes.fromhex(previous_block_hash)[::-1]
    merkle_le = bytes.fromhex(merkle_root)[::-1]
    time_bytes = struct.pack("<I", int(timestamp))
    bits = struct.pack("<I", 0x1f00ffff)
    nonce = 0
    while True:
        nonce_bytes = struct.pack("<I", nonce)
        header = version + prev_block_le + merkle_le + time_bytes + bits + nonce_bytes
        h = hashlib.sha256(header).digest()[::-1]
        if int.from_bytes(h, "big") < DIFFICULTY_TARGET:
            return header.hex(), nonce
        nonce += 1

def main():
    transactions = read_transactions()
    mempool_txids = [compute_txid(tx) for tx in transactions]
    coinbase_tx, coinbase_txid = create_coinbase_tx()
    txids = [coinbase_txid] + mempool_txids
    merkle_root = simple_merkle_root(txids)
    previous_block_hash = "0000abcd" + "0" * 56
    current_time = int(time.time())
    header, nonce = mine_block(previous_block_hash, merkle_root, current_time)

    with open("out.txt", "w") as f:
        f.write(header + "\n")
        f.write(coinbase_tx + "\n")
        for txid in txids:
            f.write(txid + "\n")

if __name__ == "__main__":
    main()
