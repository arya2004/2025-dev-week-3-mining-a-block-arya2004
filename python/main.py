import os
import json
import hashlib
import struct
import time

DIFFICULTY_TARGET = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)
MEMPOOL_DIR = "mempool"
MAX_BLOCK_WEIGHT = 4000000
WITNESS_RESERVED_VALUE = b"\x00" * 32

def read_transactions():
    transactions = []
    for filename in sorted(os.listdir(MEMPOOL_DIR)):
        if filename.endswith(".json") and filename != "mempool.json":
            txid = filename[:-5]
            with open(os.path.join(MEMPOOL_DIR, filename), "r") as f:
                tx = json.load(f)
            transactions.append((txid, tx))
    return transactions

def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def compute_witness_merkle_root_from_wtxids(wtxids):
    level = [bytes.fromhex(txid)[::-1] for txid in wtxids]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [double_sha256(level[i] + level[i+1]) for i in range(0, len(level), 2)]
    return level[0]

def create_coinbase_tx(witness_merkle_root):
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
    commitment_hash = double_sha256(witness_merkle_root + WITNESS_RESERVED_VALUE)
    script2 = b"\x6a\x24\xaa\x21\xa9\xed" + commitment_hash
    value2 = struct.pack("<Q", 0)
    tx_out2 = value2 + bytes([len(script2)]) + script2
    locktime = struct.pack("<I", 0)
    non_witness = version + in_count + tx_in + out_count + tx_out1 + tx_out2 + locktime
    coinbase_legacy_txid = double_sha256(non_witness)[::-1].hex()
    witness = b"\x01" + bytes([32]) + WITNESS_RESERVED_VALUE
    marker_flag = b"\x00\x01"
    full_tx = version + marker_flag + in_count + tx_in + out_count + tx_out1 + tx_out2 + witness + locktime
    coinbase_wtxid = double_sha256(full_tx)[::-1].hex()
    return full_tx.hex(), coinbase_legacy_txid, coinbase_wtxid

def simple_merkle_root(txids):
    if not txids:
        return "0" * 64
    level = [bytes.fromhex(txid)[::-1] for txid in txids]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [double_sha256(level[i] + level[i+1]) for i in range(0, len(level), 2)]
    return level[0][::-1].hex()

def mine_block(previous_block_hash, merkle_root, timestamp):
    version = struct.pack("<I", 4)
    prev_block_le = bytes.fromhex(previous_block_hash)[::-1]
    merkle_bytes = bytes.fromhex(merkle_root)[::-1]
    time_bytes = struct.pack("<I", int(timestamp))
    bits = struct.pack("<I", 0x1f00ffff)
    nonce = 0
    while True:
        nonce_bytes = struct.pack("<I", nonce)
        header = version + prev_block_le + merkle_bytes + time_bytes + bits + nonce_bytes
        h = double_sha256(header)[::-1]
        if int.from_bytes(h, "big") < DIFFICULTY_TARGET:
            return header.hex(), nonce
        nonce += 1

def main():
    tx_list = read_transactions()
    mempool_txids = []
    mempool_wtxids = []
    total_weight = 0
    for txid, tx in tx_list:
        weight = int(tx.get("weight", 0))
        if total_weight + weight <= MAX_BLOCK_WEIGHT:
            mempool_txids.append(txid)
            total_weight += weight
            wtxid = double_sha256(bytes.fromhex(tx["hex"]))[::-1].hex()
            mempool_wtxids.append(wtxid)
        else:
            break
    wtxids_for_commitment = ["00" * 32] + mempool_wtxids
    witness_merkle_root = compute_witness_merkle_root_from_wtxids(wtxids_for_commitment)
    coinbase_full_hex, coinbase_legacy_txid, coinbase_wtxid = create_coinbase_tx(witness_merkle_root)
    block_txids = [coinbase_legacy_txid] + mempool_txids
    merkle_root = simple_merkle_root(block_txids)
    previous_block_hash = "0000abcd" + "0" * 56
    current_time = int(time.time())
    header, nonce = mine_block(previous_block_hash, merkle_root, current_time)
    with open("out.txt", "w") as f:
        f.write(header + "\n")
        f.write(coinbase_full_hex + "\n")
        for txid in block_txids:
            f.write(txid + "\n")

if __name__ == "__main__":
    main()
