import os
import json
import hashlib
import struct
import time

DIFFICULTY_TARGET = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)
MEMPOOL_DIR = "mempool"
MAX_BLOCK_WEIGHT = 4000000

def read_transactions():
    transactions = []
    for filename in sorted(os.listdir(MEMPOOL_DIR)):
        if filename.endswith(".json"):
            txid = filename[:-5]
            with open(os.path.join(MEMPOOL_DIR, filename), "r") as f:
                tx = json.load(f)
            transactions.append((txid, tx))
    return transactions

def double_sha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def compute_witness_merkle_root(witness_hashes):
    if not witness_hashes:
        return b'\x00' * 32
    hashes = witness_hashes[:]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [double_sha256(hashes[i] + hashes[i+1]) for i in range(0, len(hashes), 2)]
    return hashes[0]

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
    value2 = struct.pack("<Q", 0)
    script2 = b"\x6a" + b"\x24" + b"\xaa\x21\xa9\xed" + witness_merkle_root
    script2_len = bytes([len(script2)])
    tx_out2 = value2 + script2_len + script2
    locktime = struct.pack("<I", 0)
    non_witness = version + in_count + tx_in + out_count + tx_out1 + tx_out2 + locktime
    coinbase_txid = double_sha256(non_witness)[::-1].hex()
    marker_flag = b"\x00\x01"
    witness = b"\x01" + bytes([32]) + (b"\x00" * 32)
    full_tx = version + marker_flag + in_count + tx_in + out_count + tx_out1 + tx_out2 + witness + locktime
    return full_tx.hex(), coinbase_txid, non_witness.hex()

def simple_merkle_root(txids):
    if not txids:
        return "0" * 64
    hashes = txids[:]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [hashlib.sha256((hashes[i] + hashes[i+1]).encode()).hexdigest() for i in range(0, len(hashes), 2)]
    return hashes[0]

def get_tx_weight(non_witness_hex, full_tx_hex):
    return len(bytes.fromhex(non_witness_hex)) * 3 + len(bytes.fromhex(full_tx_hex))

def mine_block(previous_block_hash, merkle_root, timestamp):
    version = struct.pack("<I", 4)
    prev_block_le = bytes.fromhex(previous_block_hash)[::-1]
    merkle_be = bytes.fromhex(merkle_root)
    time_bytes = struct.pack("<I", int(timestamp))
    bits = struct.pack("<I", 0x1f00ffff)
    nonce = 0
    while True:
        nonce_bytes = struct.pack("<I", nonce)
        header = version + prev_block_le + merkle_be + time_bytes + bits + nonce_bytes
        h = hashlib.sha256(header).digest()[::-1]
        if int.from_bytes(h, "big") < DIFFICULTY_TARGET:
            return header.hex(), nonce
        nonce += 1

def main():
    tx_list = read_transactions()
    selected_txs = []
    mempool_txids = []
    coinbase_witness_hash = b'\x00' * 32
    empty_witness_hash = double_sha256(b'')
    temp_witness_hashes = [coinbase_witness_hash]
    total_weight = 0
    mempool_weights = [(txid, tx, len(json.dumps(tx, sort_keys=True).encode()) * 4) for txid, tx in tx_list]
    dummy_witness_root = b'\x00' * 32
    coinbase_full_hex, coinbase_txid, coinbase_non_witness_hex = create_coinbase_tx(dummy_witness_root)
    coinbase_weight = get_tx_weight(coinbase_non_witness_hex, coinbase_full_hex)
    total_weight += coinbase_weight
    for txid, tx, weight in mempool_weights:
        if total_weight + weight <= MAX_BLOCK_WEIGHT:
            selected_txs.append(tx)
            total_weight += weight
            mempool_txids.append(txid)
            temp_witness_hashes.append(empty_witness_hash)
        else:
            break
    witness_merkle_root = compute_witness_merkle_root(temp_witness_hashes)
    coinbase_full_hex, coinbase_txid, coinbase_non_witness_hex = create_coinbase_tx(witness_merkle_root)
    txids = [coinbase_txid] + mempool_txids
    merkle_root = simple_merkle_root(txids)
    previous_block_hash = "0000abcd" + "0" * 56
    current_time = int(time.time())
    header, nonce = mine_block(previous_block_hash, merkle_root, current_time)
    
    with open("out.txt", "w") as f:
        f.write(header + "\n")
        f.write(coinbase_full_hex + "\n")
        for txid in txids:
            f.write(txid + "\n")

if __name__ == "__main__":
    main()
