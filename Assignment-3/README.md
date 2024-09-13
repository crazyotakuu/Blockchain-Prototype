Project Overview:
    This project involves a miner, 2 nodes, and 4 wallets (1 miner wallet and 3 general wallets).

Step-by-Step Execution:
    Node Setup:
        Start by running the two nodes. These nodes serve as read nodes for wallet information.

    Miner Activation:
        Next, launch the miner. The miner validates transactions and creates blocks. When a transaction is validated, it moves from pending to processed, and a block is generated(When the miner is ran for the first time it waits for 40 seconds before execution, just so you have enough time to run the wallets, from the second time it only waits 20 seconds. The miner here follows the independent criteria of running every 20 seconds and creating a block with the pending transactions.). Both the transactions and blocks are then transmitted to the two nodes.
        
    Miner Wallet Configuration:
        Proceed to set up the miner wallet. This is the wallet used by the miner for transactions.

    General Wallets Setup (all of them if needed):
        If necessary, set up all the three general wallets. These wallets are for other users in the network.

    Inter-Entity Communication:
        All communication between different entities (miner, nodes, wallets) occurs through socket connections.

    Nodes Functionality:
        Nodes primarily serve as read nodes. Wallets retrieve account balance information from them.

    Miner Rewarding Process:
        When the miner creates a block, it rewards itself with 5 units (as specified in the input file). It prompts for confirmation of the reward amount. To proceed smoothly, first provide 6 as input, then in the next iteration, provide 5. Once 5 is confirmed, the block is created and sent to the nodes.
        
    Additional Packages Installation:
        pip install cryptography

Make sure you have installed the necessary additional packages.