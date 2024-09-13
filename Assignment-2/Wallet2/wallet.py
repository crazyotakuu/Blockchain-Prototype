import os
import json
import datetime
import hashlib
import time




from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.exceptions import InvalidSignature


# Define constants
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH= os.path.dirname(os.getcwd())+"/PublicKeys/"
TRANSACTIONS_PATH = "transactions"
ACCOUNT_FILE="../accounts.json"


def genPrivateKey():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    with open(PRIVATE_KEY_PATH, "wb") as fp:
        fp.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        fp.close()

    public_pair = genPublicPair(private_key)
    # public_key = private_key.public_key()

    # public_key_hash=createUserHash(public_key)

    # key_pair={"private_key":private_key,"public_key":public_key,"public_key_hash":public_key_hash}
    os.makedirs(os.path.dirname(PUBLIC_KEY_PATH), exist_ok=True)
    with open(PUBLIC_KEY_PATH+public_pair['public_key_hash']+".pem", "wb") as fp:
        fp.write(public_pair['public_key'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        fp.close()

    return private_key


def genPublicPair(private_key):
    public_key = private_key.public_key()
    public_key_hash=createUserHash(public_key)
    public_pair={"public_key":public_key,"public_key_hash":public_key_hash}
    return public_pair


def loadPrivateKey():
    with open(PRIVATE_KEY_PATH, "rb") as fp:
        private_key = serialization.load_pem_private_key(
            fp.read(),
            password=None,
            backend=default_backend()
        )
        fp.close()
    return private_key


def createUserHash(public_key):
    user_address = hashes.Hash(hashes.SHA256(), backend=default_backend())
    user_address.update(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    hashed_address = user_address.finalize()
    return hashed_address.hex()


def signTransaction(private_key, transaction):
    signature = private_key.sign(
        json.dumps(transaction).encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def saveJSON(transaction):
    transaction_json=json.dumps(transaction)
    hash_value = computeHash(transaction_json)
    file_path="../Pending/"

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path+hash_value+".json", "w") as fp:
        fp.write(transaction_json)
        fp.close()
    
    # if not os.path.exists("../Pending"):
    #     os.makedirs("Pending")

    # with open(file_path, 'w') as fp:
    #     fp.

def computeHash(transaction_json):
    json_byte_stream=transaction_json.encode('utf-8')
    # print(hashlib.sha256(json_byte_stream).hexdigest())
    return hashlib.sha256(json_byte_stream).hexdigest()

def getBalance(account):
    with open(ACCOUNT_FILE, 'r') as fp:
            balances = json.load(fp)
            fp.close()
            return balances[account]



# Main function
def main():
    if not os.path.exists(PRIVATE_KEY_PATH):
        private_key = genPrivateKey()
        public_key_pair= genPublicPair(private_key)
        print("Congratulations! You have created a new Account")
        initial_balance=input('Enter the amount you want to buy from genesis account: ')
        transaction_timestamp=int(datetime.datetime.now().timestamp())
        transaction = {"Timestamp":transaction_timestamp,"From":"genesis_account","To":public_key_pair['public_key_hash'],"Amount":initial_balance}
        sign=signTransaction(private_key,transaction)
        sign=sign.hex()
        signed_transaction={"content":transaction,"sign":sign}
        saveJSON(signed_transaction)
        time.sleep(10)
    else:
        private_key=loadPrivateKey()
        public_key_pair=genPublicPair(private_key)

    action = input('What do you want to do?\n Enter 1 - Check Balance, 2 - Create a Transaction, 3 - Check Other Account\'s Balance : ')
    if action == "1":
        balance = getBalance(public_key_pair['public_key_hash'])
        print(balance)
    elif action == "2":
        transaction_to=input('Please enter the reciever details\n')
        transaction_amount=input('Please enter the amount\n')
        transaction_timestamp=int(datetime.datetime.now().timestamp())
        transaction = {"Timestamp":transaction_timestamp,"From":public_key_pair["public_key_hash"],"To":transaction_to,"Amount":transaction_amount}
        sign=signTransaction(private_key,transaction)
        sign=sign.hex()
        # print(sign)
        # print(type(sign))
        signed_transaction={"content":transaction,"sign":sign}
        saveJSON(signed_transaction)
    elif action=="3":
        address = input("Enter Account Id: ")
        balance = getBalance(address)
        print(balance)

    # transaction_from=input('Please enter the sender details\n')
    



if __name__ == "__main__":
    main()
