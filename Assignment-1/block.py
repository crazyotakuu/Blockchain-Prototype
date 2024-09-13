from transaction import computeHash
import datetime
import json
import os

PENDING_DIR="pending"
PROCESSED_DIR="processed"
BLOCK_DETAILS_FILE="blockdetails.json"
BLOCK_DIR="blocks"

def main():
    block_body=writeBody(PENDING_DIR)
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


def writeBody(PENDING_DIR):
    body=[]
    if not os.path.exists(PROCESSED_DIR):
            os.mkdir(PROCESSED_DIR)

    for file in os.listdir(PENDING_DIR):
        with open(PENDING_DIR+"/"+file,"r") as fp:
            body_data= {"hash":file.removesuffix(".json"),"content":json.load(fp)}
            body.append(body_data)
            fp.close()
        os.rename(PENDING_DIR+"/"+file,PROCESSED_DIR+"/"+file)
    return body

if __name__=="__main__":
    main()