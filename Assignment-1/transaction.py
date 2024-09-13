import json
import datetime
import hashlib
import os

def main():
    transaction_from=input('Please enter the sender details\n')
    transaction_to=input('Please enter the reciever details\n')
    transaction_amount=input('Please enter the amount\n')
    transaction_timestamp=int(datetime.datetime.now().timestamp())
    transaction = {"Timestamp":transaction_timestamp,"From":transaction_from,"To":transaction_to,"Amount":transaction_amount}
    saveJSON(transaction)

def saveJSON(transaction):
    transaction_json=json.dumps(transaction)
    hash_value = computeHash(transaction_json)
    file_path="pending/"+hash_value+".json"
    
    if not os.path.exists("pending"):
        os.makedirs("pending")

    with open(file_path, 'w') as fp:
        fp.write(transaction_json)
    
    
def computeHash(transaction_json):
    json_byte_stream=transaction_json.encode('utf-8')
    # print(hashlib.sha256(json_byte_stream).hexdigest())
    return hashlib.sha256(json_byte_stream).hexdigest()

if __name__ == "__main__":
    main()  