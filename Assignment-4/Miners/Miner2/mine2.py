import asyncio
import os
import random
import json
import hashlib
import socket
import datetime
import random
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

PENDING_DIR="./Pending"
PRE_PROCESSED_DIR="./PreProcessed"
PROCESSED_DIR="./Processed"
REJECTED_DIR="./Rejected"
PUBLIC_DIR="./PublicKeys"
BLOCK_DIR="./Blocks"
ACCOUNT_FILE="accounts.json"
BLOCK_DETAILS_FILE="blockdetails.json"
WALLET_ADDRESS=""

balances = {}
miner= 49505
miner_and_nodes={1:49155,2:49156,3:49505}


def handle_public_key(public_key):
    user_hash=createUserHash(public_key)
    with open(PUBLIC_DIR+"/"+user_hash+".pem", "wb") as fp:
        fp.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def createUserHash(public_key):
    user_address = hashes.Hash(hashes.SHA256(), backend=default_backend())
    user_address.update(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    hashed_address = user_address.finalize()
    return hashed_address.hex()


def handle_transaction(transaction):
    transaction_json=json.dumps(transaction)
    hash_value = computeHash(transaction_json)
    with open(PENDING_DIR+"/"+hash_value+".json", "w") as fp:
        fp.write(transaction_json)
        fp.close()

def handle_miner_public_key(publickey):
    global WALLET_ADDRESS
    decoded_public_key_bytes = base64.b64decode(publickey)
    public_key = serialization.load_pem_public_key(decoded_public_key_bytes, backend=default_backend())
    user_hash=createUserHash(public_key)
    WALLET_ADDRESS=user_hash
    with open(PUBLIC_DIR+"/"+"miner_public_key"+".pem", "wb") as fp:
        fp.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    with open(PUBLIC_DIR+"/"+user_hash+".pem", "wb") as fp:
        fp.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    

def computeHash(transaction_json):
    json_byte_stream=transaction_json.encode('utf-8')
    return hashlib.sha256(json_byte_stream).hexdigest()


async def handle_client(reader, writer):
    data = await reader.read(4096)
    try:
        message = data.decode()
        message = json.loads(data)
        if 'id' in message:
            if message['id'] == "transaction":
                handle_transaction(message["signed_transaction"])
            elif message['id'] == "miner_public_key":
                handle_miner_public_key(message["public_key"])
            else:
                print("Invalid message format.")
        else:
            print("Missing 'id' in message.")
    except json.JSONDecodeError as e:
        try:
            public_key = serialization.load_pem_public_key(data, backend=default_backend())
            handle_public_key(public_key)
        except Exception as e:
            print(f"Error: {e}")

    writer.close()

async def start_server():
    server = await asyncio.start_server(
        handle_client, 'localhost', 49506)

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

def loadpublickey():
    global WALLET_ADDRESS
    with open(PUBLIC_DIR+"/"+"miner_public_key"+".pem", "rb") as fp:
        pem_data = fp.read()
        public_key = serialization.load_pem_public_key(pem_data)
    user_hash=createUserHash(public_key)
    WALLET_ADDRESS=user_hash


def writeToMinerandNodes(input):
    input_json = json.dumps(input)
    for i in miner_and_nodes:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("localhost", miner_and_nodes[i]))
            client_socket.send(input_json.encode())
            client_socket.close()

def writeToMiner(input):
    input_json = json.dumps(input)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", miner))
    client_socket.send(input_json.encode())
    client_socket.close()


def handle_coinbase_transaction(block_data):
    global WALLET_ADDRESS
    flag = True
    while flag:
        transaction_amount = int(input("Please enter the reward amount of 5: "))
        transaction_timestamp=int(datetime.datetime.now().timestamp())
        coinbase_transaction={"Timestamp":transaction_timestamp,"From":"Mining","To":WALLET_ADDRESS,"Amount":transaction_amount}
        transaction_json=json.dumps(coinbase_transaction)
        hash = computeHash(transaction_json)
        body_data= {"hash": hash,"content":coinbase_transaction}
        block_data.insert(0, body_data)
        if validate_transaction(coinbase_transaction):
            update_balance(coinbase_transaction)
            flag = False
            return block_data


async def main():
    global balances
    os.makedirs(PENDING_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(REJECTED_DIR, exist_ok=True)
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    os.makedirs(BLOCK_DIR, exist_ok=True)
    if os.path.exists(PUBLIC_DIR+"/"+"miner_public_key"+".pem"):
        loadpublickey()
    createGenesisAccount()
    server_task = asyncio.create_task(start_server())
    await asyncio.sleep(random.randint(25, 30))
    while True:
        files = os.listdir(PENDING_DIR)
        file_count = len(files)
        if file_count==0:
            pass
        else:
            with open(ACCOUNT_FILE, 'r') as fp:
                balances = json.load(fp)
                fp.close()
            block_body=writeBody()
            if block_body!=0 and block_body != []:
                createBlock(block_body)
                with open(ACCOUNT_FILE, 'w') as fp:
                    json.dump(balances, fp)
                    fp.close()
        
def createBlock(block_body):
    block_data = None
    new_block_details = None
    hash_value_body = computeHash(json.dumps(block_body))
    if not os.path.exists(BLOCK_DETAILS_FILE):
        header={"height":0,"timestamp":int(datetime.datetime.now().timestamp()),"previousblock":"NA","hash":hash_value_body}
        block_body=handle_coinbase_transaction(block_body)
        block_data={"header":header,"body":block_body}
        hash_value_block=computeHash(json.dumps(block_data))
        block_details={"height":1,"previousblock":hash_value_block}
        with open(BLOCK_DETAILS_FILE, 'w') as fp:
            fp.write(json.dumps(block_details))
            fp.close()
        with open(BLOCK_DIR+"/"+hash_value_block+".json", 'w') as fp:
                fp.write(json.dumps(block_data))
                fp.close()
    else:
        with open(BLOCK_DETAILS_FILE,'r')as fp:
            block_details=json.load(fp)
            fp.close()
        # print(block_details)
        header={"height":block_details['height'],"timestamp":int(datetime.datetime.now().timestamp()),"previousblock":block_details['previousblock'],"hash":hash_value_body}
        block_body=handle_coinbase_transaction(block_body)
        block_data={"header":header,"body":block_body}
        hash_value_block=computeHash(json.dumps(block_data))
        new_block_height=block_details['height']+1
        new_block_details={"height":new_block_height,"previousblock":hash_value_block}

        with open(BLOCK_DETAILS_FILE, 'w') as fp:
            fp.write(json.dumps(new_block_details))
            fp.close()
        with open(BLOCK_DIR+"/"+hash_value_block+".json", 'w') as fp:
            fp.write(json.dumps(block_data))
            fp.close()
    block_data_to_send={"id":"block_data","block_data":block_data}
    writeToNodes(block_data_to_send)
    block_details_to_send={"id":"block_details","block_details":new_block_details}
    writeToNodes(block_details_to_send)


def writeBody():
    global balances
    body=[]
    files = os.listdir(PENDING_DIR)
    # Get the count of files
    file_count = len(files)
    for file in files:
        with open(PENDING_DIR+"/"+file,"r") as fp:
            transaction=json.load(fp)
            if verify_signature(transaction):
                if validate_transaction(transaction['content']):
                    body_data= {"hash":file.removesuffix(".json"),"content":transaction}
                    body.append(body_data)
                    fp.close()
                    update_balance(transaction['content'])
                    os.rename(PENDING_DIR+"/"+file,PROCESSED_DIR+"/"+file)
                    transaction_to_send={"id":"transaction","transaction":transaction}
                    writeToNodes(transaction_to_send)
                    continue
            fp.close()
            os.rename(PENDING_DIR+"/"+file,REJECTED_DIR+"/"+file)
    if file_count==0:
        return 0
    return body


def update_balance(transaction):
    global balances
    if transaction["From"]=="Mining":
        if transaction["To"] in balances:
            balances[transaction["To"]]+=float(transaction["Amount"])
        else:
            balances[transaction["To"]]=float(transaction["Amount"])
    elif transaction["From"]=="genesis_account":
        balances[transaction["From"]]=float(balances[transaction["From"]])-float(transaction["Amount"])
        balances[transaction["To"]]=float(transaction["Amount"])
    else:
        balances[transaction["From"]]=float(balances[transaction["From"]])-float(transaction["Amount"])
        balances[transaction["To"]]=float(balances[transaction["To"]])+float(transaction["Amount"])
    

def validate_transaction(transaction):
    global balances
    # print(transaction)
    if transaction['To'] in balances or transaction["From"]=="genesis_account" or transaction["From"]=="Mining":
        if transaction["From"]=="Mining":
            if transaction["Amount"] == 5:
                return True
            else:
                return False
        elif float(balances[transaction["From"]])>=float(transaction["Amount"]):
            return True
        else:
            return False
    else:
        return False


def verify_signature(transaction):
    global balances
    if transaction["content"]["From"]=="genesis_account":
        return True
    public_key_file="PublicKeys/"+transaction["content"]["From"]+".pem"
    with open(public_key_file, "rb") as fp:
        public_key = serialization.load_pem_public_key(
        fp.read(),
        backend=default_backend()
        )
        fp.close()
    signature = bytes.fromhex(transaction['sign'])
    try:
        public_key.verify(
            signature,
            json.dumps(transaction['content']).encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
        
    
if __name__ == "__main__":
    try:
        asyncio.run(main())
        pass
    except KeyboardInterrupt:
        print("\nProgram closed.")
