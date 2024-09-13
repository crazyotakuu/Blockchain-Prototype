import asyncio
import os
import time
import json
import hashlib
import socket
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


PROCESSED_DIR="./Transactions"
BLOCK_DIR="./Blocks"
ACCOUNT_FILE="accounts.json"
BLOCK_DETAILS_FILE="blockdetails.json"
balances={}    

async def handle_block_data(data):
    # print(data)
    data=data['data']
    handle_block_details(data)
    handle_balance(data)
    block=data["block_data"]
    hash_value_block=data["block_details"]['previousblock']
    if int(data["block_details"]['height']) ==1:
        with open(BLOCK_DIR+"/"+hash_value_block+".json", 'w') as fp:
            fp.write(json.dumps(block))
            fp.close()
    else:
        if validateBlock(block):
            with open(BLOCK_DIR+"/"+hash_value_block+".json", 'w') as fp:
                fp.write(json.dumps(block))
                fp.close()
        else:
            print("invalid block detected")

def handle_balance(data):
    print(data)
    balances=data["balance_details"]
    with open(ACCOUNT_FILE, 'w') as fp:
        json.dump(balances, fp)
        fp.close()

def validateBlock(block):
    # print("hehehe")
    # print(block)
    flag0=validateTransactions(block['body'])
    flag1=True
    body_json=json.dumps(block['body'])
    body_hash=computeHash(body_json)
    hash = block['header']['hash']
    if body_hash== hash:
        flag1=True
    flag2=False
    previous_block=block['header']['previousblock']+".json"
    previous_block_path = os.path.join(BLOCK_DIR, previous_block)
    # print(previous_block)
    # print(previous_block_path)
    # Check if the previous block file exists
    if os.path.exists(previous_block_path):
        with open(previous_block_path, 'r') as file:
            data_in_file = json.load(file)
            previous_height = int(data_in_file['header']['height'])
            # Compare the height of the previous block with the new block
            if previous_height + 1 == int(block['header']['height']):
                flag2=True
    # print(flag0,flag1,flag2)
    if flag0 and flag1 and flag2:
        return True
    else:
        return False
    
    

    
def validateTransactions(transactions):
    processed_files = os.listdir(PROCESSED_DIR)
    # print(processed_files)
    # Check each transaction
    for transaction in transactions:
        # print(transaction)
        if 'From' in transaction['content']:
            if transaction['content']['From'] == "Mining":
                pass
        else:
            transaction=transaction['content']
            # print(transaction)
            transaction_json = json.dumps(transaction)
            transaction_hash = computeHash(transaction_json) + ".json"
            # print(transaction_hash)

            # If any transaction hash is not in processed_files, return False
            if transaction_hash not in processed_files:
                return False

    # All transactions are in processed_files, return True
    return True



def handle_block_details(data):
    block_details=data["block_details"]
    with open(BLOCK_DETAILS_FILE, 'w') as fp:
        fp.write(json.dumps(block_details))
        fp.close()

async def handle_transaction(data):
    # print("hii")
    # print(data)
    transaction=data["signed_transaction"]
    transaction_json=json.dumps(transaction)
    hash_value = computeHash(transaction_json)
    with open(PROCESSED_DIR+"/"+hash_value+".json", "w") as fp:
        fp.write(transaction_json)
        fp.close()

async def handle_operation(data):
    global balances
    user_id=data["user_address"]
    response = balances.get(user_id)
    # print(response)
    return {"balance": response}

    
def computeHash(transaction_json):
    json_byte_stream=transaction_json.encode('utf-8')
    return hashlib.sha256(json_byte_stream).hexdigest()

async def handle_data(data, writer):
    id_type = data.get("id")
    if id_type == "block":
        await handle_block_data(data)
    elif id_type == "transaction":
        await handle_transaction(data)
    elif id_type == "operation":
        response = await handle_operation(data)
        print(response)
        if response is not None:
            # print(f"Sent balance: {response['balance']}")
            writer.write(json.dumps(response).encode())
            await writer.drain()
    else:
        print(f"Unknown data type with id: {id_type}")

async def handle_client(reader, writer):
    data = await reader.read(4096)
    message = data.decode('utf-8')
    # print(f"Received message: {message}")
    
    try:
        data = json.loads(message)
        await handle_data(data, writer)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    
    writer.close()

async def setup_server():
    server = await asyncio.start_server(
        handle_client, '127.0.0.1', 49508)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

def createGenesisAccount():
    if not os.path.exists(ACCOUNT_FILE):
        genesis_account={"genesis_account":3000}
        with open(ACCOUNT_FILE, "w") as fp:
            fp.write(json.dumps(genesis_account))
            fp.close()

def main():
    global balances
    createGenesisAccount()
    with open(ACCOUNT_FILE, 'r') as fp:
        balances = json.load(fp)
        fp.close()
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(BLOCK_DIR, exist_ok=True)
    asyncio.run(setup_server())

if __name__ == "__main__":
    try:
        main()
        pass
    except KeyboardInterrupt:
        print("\nProgram closed.")
