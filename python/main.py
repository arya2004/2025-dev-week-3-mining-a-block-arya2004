import os
import json
import hashlib

# Constants
DIFFICULTY_TARGET = int("0000ffff00000000000000000000000000000000000000000000000000000000", 16)
MEMPOOL_DIR = "mempool"

def read_transactions():

    transactions = []
    for file in sorted(os.listdir(MEMPOOL_DIR)): 
        if file.endswith(".json"):
            with open(os.path.join(MEMPOOL_DIR, file), "r") as f:
                tx = json.load(f)
                transactions.append(tx)
    return transactions

def compute_txid(transaction):
    tx_json = json.dumps(transaction, sort_keys=True).encode()
    return hashlib.sha256(tx_json).hexdigest()

def create_coinbase_tx():
    coinbase_tx = {"txid": "COINBASE_TX", "data": "Reward Transaction"}
    coinbase_txid = compute_txid(coinbase_tx)
    return coinbase_tx, coinbase_txid

def mine_block(previous_block_hash, merkle_root, timestamp):
    nonce = 0
    while True:
        block_header = f"{previous_block_hash}{merkle_root}{timestamp}{nonce}"
        block_hash = hashlib.sha256(block_header.encode()).hexdigest()
        if int(block_hash, 16) < DIFFICULTY_TARGET:
            return block_hash, nonce
        nonce += 1

def compute_merkle_root(txids):
    if not txids:
        return "0" * 64  # Default empty Merkle root
    
    while len(txids) > 1:
        if len(txids) % 2 == 1:
            txids.append(txids[-1])  # Duplicate last TXID if odd number of transactions
        txids = [hashlib.sha256((a + b).encode()).hexdigest() for a, b in zip(txids[0::2], txids[1::2])]
    
    return txids[0]

def main():
    print("Reading transactions from the mempool...")
    transactions = read_transactions()
    print(f"Read {len(transactions)} transactions.")
    txids = []
    for tx in transactions:
        txids.append(compute_txid(tx))

    print(f"Computed {len(txids)} transaction IDs.")

    coinbase_tx, coinbase_txid = create_coinbase_tx()
    txids.insert(0, coinbase_txid)  

    merkle_root = compute_merkle_root(txids)

   
    previous_block_hash = "0000abcd" + "0" * 56 

  
    timestamp = "1700000000"


    block_hash, nonce = mine_block(previous_block_hash, merkle_root, timestamp)


    with open("out.txt", "w") as f:
        f.write(f"{block_hash}\n")
        f.write(f"{json.dumps(coinbase_tx)}\n")
        f.write("\n".join(txids) + "\n")  

if __name__ == "__main__":
    main()
