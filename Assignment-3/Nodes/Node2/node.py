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


PROCESSED_DIR="./Processed"
BLOCK_DIR="./Blocks"
ACCOUNT_FILE="accounts.json"
BLOCK_DETAILS_FILE="blockdetails.json"
balances={}

async def handle_balance(data):
    global balances
    balances=data["balance"]
    with open(ACCOUNT_FILE, 'w') as fp:
        json.dump(balances, fp)
        fp.close()
    

async def handle_block_data(data):
    block_data=data["block_data"]
    hash_value_block=computeHash(json.dumps(block_data))
    with open(BLOCK_DIR+"/"+hash_value_block+".json", 'w') as fp:
        fp.write(json.dumps(block_data))
        fp.close()

async def handle_block_details(data):
    block_details=data["block_details"]
    with open(BLOCK_DETAILS_FILE, 'w') as fp:
        fp.write(json.dumps(block_details))
        fp.close()

async def handle_transaction(data):
    transaction=data["transaction"]
    transaction_json=json.dumps(transaction)
    hash_value = computeHash(transaction_json)
    with open(PROCESSED_DIR+"/"+hash_value+".json", "w") as fp:
        fp.write(transaction_json)
        fp.close()

async def handle_operation(data):
    global balances
    user_id=data["user_address"]
    response = balances.get(user_id)
    print(response)
    return {"balance": response}

    
def computeHash(transaction_json):
    json_byte_stream=transaction_json.encode('utf-8')
    return hashlib.sha256(json_byte_stream).hexdigest()

async def handle_data(data, writer):
    id_type = data.get("id")
    if id_type == "balance":
        await handle_balance(data)
    elif id_type == "block_data":
        await handle_block_data(data)
    elif id_type == "block_details":
        await handle_block_details(data)
    elif id_type == "transaction":
        await handle_transaction(data)
    elif id_type == "operation":
        response = await handle_operation(data)
        print(response)
        if response is not None:
            print(f"Sent balance: {response['balance']}")
            writer.write(json.dumps(response).encode())
            await writer.drain()
    else:
        print(f"Unknown data type with id: {id_type}")

async def handle_client(reader, writer):
    data = await reader.read(4096)
    message = data.decode()
    print(f"Received message: {message}")
    
    try:
        data = json.loads(message)
        await handle_data(data, writer)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    
    writer.close()

async def setup_server():
    server = await asyncio.start_server(
        handle_client, '127.0.0.1', 49156)

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
