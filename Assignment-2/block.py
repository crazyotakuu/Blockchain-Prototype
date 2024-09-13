import datetime
import json
import os
import hashlib
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


PENDING_DIR="Pending"
# PROCESSED_DIR=os.path.dirname(os.getcwd())+"/Processed"
PROCESSED_DIR="./Processed"
BLOCK_DETAILS_FILE="blockdetails.json"
# REJECTED_DIR=os.path.dirname(os.getcwd())+"/Rejected"
REJECTED_DIR="./Rejected"
BLOCK_DIR="Blocks"
ACCOUNT_FILE="accounts.json"
balances = {}

def main():
    global balances
    createGenesisAccount()
    while True:
        with open(ACCOUNT_FILE, 'r') as fp:
            balances = json.load(fp)
            fp.close()
        # balances = {account['Address']: account['Balance'] for account in accounts_data}
        block_body=writeBody()
        if block_body!=0:
            createBlock(block_body)
            with open(ACCOUNT_FILE, 'w') as fp:
                json.dump(balances, fp)
                fp.close()
        time.sleep(5)
    

def createGenesisAccount():
    if not os.path.exists(ACCOUNT_FILE):
        genesis_account={"genesis_account":3000}
        with open(ACCOUNT_FILE, "w") as fp:
            fp.write(json.dumps(genesis_account))
            fp.close()


def createBlock(block_body):
    hash_value_body = computeHash(json.dumps(block_body))
    if not os.path.exists(BLOCK_DIR):
            os.mkdir(BLOCK_DIR)

    if not os.path.exists(BLOCK_DETAILS_FILE):
        header={"height":0,"timestamp":int(datetime.datetime.now().timestamp()),"previousblock":"NA","hash":hash_value_body}

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
        print(block_details)
        header={"height":block_details['height'],"timestamp":int(datetime.datetime.now().timestamp()),"previousblock":block_details['previousblock'],"hash":hash_value_body}
        
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


def computeHash(transaction_json):
    json_byte_stream=transaction_json.encode('utf-8')
    # print(hashlib.sha256(json_byte_stream).hexdigest())
    return hashlib.sha256(json_byte_stream).hexdigest()


def writeBody():
    global balances
    body=[]
    os.makedirs(PENDING_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(REJECTED_DIR, exist_ok=True)
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
                    continue
            fp.close()
            os.rename(PENDING_DIR+"/"+file,REJECTED_DIR+"/"+file)
    if file_count==0:
        return 0
    return body


def update_balance(transaction):
    global balances
    if transaction["From"]=="genesis_account":
        balances[transaction["From"]]=float(balances[transaction["From"]])-float(transaction["Amount"])
        balances[transaction["To"]]=float(transaction["Amount"])
    else:
        balances[transaction["From"]]=float(balances[transaction["From"]])-float(transaction["Amount"])
        balances[transaction["To"]]=float(balances[transaction["To"]])+float(transaction["Amount"])
    

def validate_transaction(transaction):
    global balances
    print(balances)
    if transaction['To'] in balances or transaction["From"]=="genesis_account":
        if float(balances[transaction["From"]])>=float(transaction["Amount"]):
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
    

if __name__=="__main__":
    main()