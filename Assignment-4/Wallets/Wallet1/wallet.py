import os
import json
import datetime
import hashlib
import time
import random
import socket



from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


PRIVATE_KEY_PATH = "private_key.pem"
miner = 49505
nodes = {1:49507,2:49508}
wallet_port=49502
public_pair={}

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
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sendPublicKey(public_key_bytes)
    genPublicPair(public_key)

    return private_key


def genPublicPair(public_key):
    global public_pair
    public_key_hash=createUserHash(public_key)
    public_pair={"public_key":public_key,"user_id":public_key_hash}


def loadPrivateKey():
    with open(PRIVATE_KEY_PATH, "rb") as fp:
        private_key = serialization.load_pem_private_key(
            fp.read(),
            password=None,
            backend=default_backend()
        )
        fp.close()
    public_key = private_key.public_key()
    # public_key_bytes = public_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )
    # sendPublicKey(public_key_bytes)
    genPublicPair(public_key)
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


def sendJSON(signed_transaction):
    transaction={"id":"transaction","signed_transaction":signed_transaction}
    transaction_json = json.dumps(transaction)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", miner))
    client_socket.send(transaction_json.encode())
    client_socket.close()


def sendPublicKey(public_key_bytes):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", miner))
    client_socket.send(public_key_bytes)
    client_socket.close()


def getBalance(account):
    result = (random.randint(1, 100) % 2)+1
    transaction={"id":"operation","user_address":account}
    transaction_json = json.dumps(transaction)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", nodes[result]))
    client_socket.send(transaction_json.encode())
    data = client_socket.recv(1024).decode()
    client_socket.close()
    return data


def main():
    if not os.path.exists(PRIVATE_KEY_PATH):
        private_key = genPrivateKey()
        print("Congratulations! You have created a new Account")
        initial_balance=input('Enter the amount you want to buy from genesis account: ')
        transaction_timestamp=int(datetime.datetime.now().timestamp())
        transaction = {"Timestamp":transaction_timestamp,"From":"genesis_account","To":public_pair['user_id'],"Amount":initial_balance}
        sign=signTransaction(private_key,transaction)
        sign=sign.hex()
        signed_transaction={"content":transaction,"sign":sign}
        sendJSON(signed_transaction)
        time.sleep(10)
    else:
        private_key=loadPrivateKey()

    action = input('What do you want to do?\n Enter 1 - Check Balance, 2 - Create a Transaction, 3 - Check Other Account\'s Balance : ')
    if action == "1":
        balance = getBalance(public_pair['user_id'])
        print(balance)
    elif action == "2":
        transaction_to=input('Please enter the reciever details\n')
        transaction_amount=input('Please enter the amount\n')
        transaction_timestamp=int(datetime.datetime.now().timestamp())
        transaction = {"Timestamp":transaction_timestamp,"From":public_pair["user_id"],"To":transaction_to,"Amount":transaction_amount}
        sign=signTransaction(private_key,transaction)
        sign=sign.hex()
        signed_transaction={"content":transaction,"sign":sign}
        sendJSON(signed_transaction)
    elif action=="3":
        address = input("Enter Account Id: ")
        balance = getBalance(address)
        print(balance)

if __name__ == "__main__":
    try:
        main()
        pass
    except KeyboardInterrupt:
        print("\nProgram closed.")
