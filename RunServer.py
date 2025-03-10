# WARNING: IN THIS CODE I CONSIDER THAT YOU HAVE A SMALL COMMUNITY OF USERS
# THIS IS NOT DESIGN FOR A BIG COMMUNITY, ELSE YOU WILL NEED RUST CODE AND  FOLK




# https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python
# import iidwshandshake 

# 
# pip install web3 eth-account websockets requests tornado --break-system-packages 
# pip install ntplib --break-system-packages
# git clone https://github.com/EloiStree/2025_01_01_HelloMegaMaskPushToIID.git /git/push_iid




# Debian: /lib/systemd/system/apintio_push_iid.service
# sudo nano /lib/systemd/system/apintio_push_iid.service
"""
[Unit]
Description=APIntIO Push IID Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /git/push_iid/RunServer.py
Restart=always
User=root
WorkingDirectory=/git/push_iid

[Install]
WantedBy=multi-user.target
"""
#1h
# sudo nano /etc/systemd/system/apintio_push_iid.timer
"""
[Unit]
Description=APIntIO Push IID Timer

[Timer]
OnBootSec=0min
OnUnitActiveSec=10s

[Install]
WantedBy=timers.target
"""

# cd /lib/systemd/system/
# sudo systemctl daemon-reload
# sudo systemctl enable apintio_push_iid.service
# chmod +x /git/push_iid/RunServer.py
# sudo systemctl enable apintio_push_iid.service
# sudo systemctl start apintio_push_iid.service
# sudo systemctl status apintio_push_iid.service
# sudo systemctl stop apintio_push_iid.service
# sudo systemctl restart apintio_push_iid.service
# sudo systemctl enable apintio_push_iid.timer
# sudo systemctl start apintio_push_iid.timer
# sudo systemctl status apintio_push_iid.timer
# sudo systemctl list-timers | grep apintio_push_iid


"""
sudo systemctl stop apintio_push_iid.service
sudo systemctl stop apintio_push_iid.timer
"""

"""
sudo systemctl restart apintio_push_iid.service
sudo systemctl restart apintio_push_iid.timer
"""







import json
import socket
import time
import traceback
from web3 import Web3
import os
from eth_account.messages import encode_defunct
import uuid
import os
import sys
import asyncio
import websockets
import struct
import requests
import queue
import threading
import tornado
import tornado.ioloop
import tornado.web
import tornado.websocket


from VerifyBit4096B58Pkcss1SHA256 import is_verify_b58rsa4096_signature
from VerifyBit4096B58Pkcss1SHA256 import is_verify_b58rsa4096_signature_no_letter_marque



# When you do some game you can trust user.
# This option override the NTP date with the server date if in the past.
bool_override_ntp_past_date=False

w3 = Web3()
ntp_server = "be.pool.ntp.org"

def get_ntp_time():
    import ntplib
    from time import ctime
    c = ntplib.NTPClient()
    response = c.request(ntp_server, version=3)
    return response.tx_time

def get_local_timestamp_in_ms_utc_since1970():
        return int(time.time()*1000)
    
def get_ntp_time_from_local():
    global millisecond_diff
    return asyncio.get_event_loop().time()*1000+millisecond_diff


ntp_timestmap = get_ntp_time()*1000
local_timestamp = get_local_timestamp_in_ms_utc_since1970()
millisecond_diff = ntp_timestmap-local_timestamp
print(f"ntp_timestmap: {ntp_timestmap}")
print(f"local_timestamp: {local_timestamp}")
print(f"diff: {millisecond_diff}")

allow_text_message = False
int_max_byte_size = 16
int_max_char_size = 16


bool_allow_coaster =True
# I NEED TO ADD A FEATURE THAT LOAD THE COASTER FROM A FILE
# If no allow identify, the coaster need to be added in the file
bool_allow_unidentify_coaster=True


# To avoid bottle neck, we can use multiple server
# Some script are they to relay the message received.
# Some script are they to send the message to the listener of an index
# Listener are more complexe that relay.
# The feature here should be disable. But by simplicity, I let it here for now.
bool_use_as_listener_to=True


RTFM= "https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python.git"

print("Hello World Python IID Listen Server")
user_index_public_index_file = "/git/APIntIO_Claim/Claims"


# If you are like 1-30 address, in code add could be usefull
# But you should prefer a file system if possible.
additionnal_in_code_add="""
-56:0x0AD2FFA0A42d43B10f848ED07604a1737c1c07Cb
-57:0xDa3239C8ad5C321A1411F3acC2C1f9F8C9D34ECE
-85:0xDa3239C8ad5C321A1411F3acC2C1f9F8C9D34ECE
  1:0xA7c02172ff523586907C201d76AB6EE4A370d0c2  
  2:0x77C724490291F7D18b9B5320B75D9d2bE609faa5  
  3:0x7E5F382863E003022757490328d03ebf33D7c2e0  
  4:0x228Ec05056F54B5660aBFE61b3eda28b4D975048  
  5:0xC1F1a74CD83d868F6E5E118b6889D5C311C9c6B4  
  6:0x76B4EF4Ca8b2D33044B1A155319fd6B486d62143  
  7:0x699E2d3aD536487238529e26FEb9683ccEA384B0  
  8:0x301a8FEe63D7B2a8af2F2E378B7A366fd8e7953c  
  9:0x8dc7aEA6fC8AAd7Db06e146Aed524db2CA30A5D4  
 10:0x82dC329171eCfBf253551D706227713CC6560AEF  
 11:0xc5E49050B1c9aAdb9e205ffc952Ea7A6DB701762  
 12:0xddf768166Cc1FfbdFCf42396fB8b215069d6FD7F  
 13:0xC1c76104106C4e68F8a40E748Ed3Eff22484bD3F  
 14:0x6CdD12C4CaaF4bcE5669f7f386d73a55ec7D1129  
 15:0xB2B8EEB186236BB7EdBd8ac6d46147F9dC03d42E  
 16:0xaF3fBC01B8f6bcBaFF5aa4C71529b79067B8f670
""".replace(" ", "")


unity_rsa_4096_in_code_add="""
-99:pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9Hy5YEoNn4FoJn61B7bP9fFwYxWMGQpZJAD2374pnfxqaj5aThoR2j5SJk8TpScHwGThbJkfwDogkVoW523YTxP69LiZkE92qcgsrcSYZfkoqFtyFXVVkN9m5o3SDNNy2pSN9eygZGvvGigJMkXGb8xREGAmvkPt8XV79UbxvoooN1HaTRJu6LwiTJ41zFrGfyZnxMVgeRsxa3brrTpYoxt2hvh1otJ3HxajWeFfvqysYadKzoC1u54C7AuZPCpSkUbzEgERDLC5f5fqJ8LTdcTsubrC5BFQZQK6YBGN3PycYEy
"""

# 7074ce50c023524f306f63ed875fb9d244b606a54e0fae5e2f1d4d3359f59649 Patato 
# 6d61374da4b4df53c6f8fbf4c9b05576d647a07da7498b400abaf7e1f4f44124 Potato
unsecure_SHA256_password_connection="""
-123:6d61374da4b4df53c6f8fbf4c9b05576d647a07da7498b400abaf7e1f4f44124
-124:872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4 

"""


## If false, the user with index < 0 will be rejected
# -integer index are key given to allow guest to use the server
bool_allow_guest_user = True
bool_allow_unregistered_user = True

## All my tools and code are around Integer Index and Ethereum Address Sign and Verify.
# RSA is still in the project because ECC is not natively in Unity3D.
# You can allows RSA user when you want to reduce friction but you should prefer ECC with MetaMask.
bool_allow_rsa_user = True
additionnal_rsa_b58key_in_code_add = """


"""

# read the file
user_index_to_address={}
user_address_to_index={}


if os.path.exists(user_index_public_index_file):
    with open(user_index_public_index_file, 'r') as file:
        text = file.read()
        lines = text.split("\n")
        for line in lines[:20]:
            if ":" in line:
                index, address = line.split(":")
                user_index_to_address[index] = address.strip()
                user_address_to_index[address] = index.strip()


print (f"Claimed index: {len(user_index_to_address)}")
dict_size = sys.getsizeof(user_index_to_address)
for key, value in user_index_to_address.items():
    dict_size += sys.getsizeof(key) + sys.getsizeof(value)
dico_size_in_mo = int(int(dict_size) / 1024 / 1024*10000) / 10000
print(f"Byte size of user_index_to_address: {dict_size}, {dico_size_in_mo} Mo")

for line in additionnal_in_code_add.split("\n"):
    if len(line)>0:
        line= line.strip("\r").strip("\n").strip()
        index, address = line.split(":")
        user_index_to_address[index] = address.strip()
        user_address_to_index[address] = index.strip()
        print(f"In code Add {index} {address}")


if bool_allow_rsa_user:
    for line in unity_rsa_4096_in_code_add.split("\n"):
        if len(line)>0:
            line= line.strip("\r").strip("\n").strip()
            index, address = line.split(":")
            user_index_to_address[index] = address.strip()
            user_address_to_index[address] = index.strip()
            print(f"In code Add {index} {address}")

# def is_message_signed_rsa(message, address, signature):




# IID is design to teach to student at the base of the design.
# If the student don't have the level to learn or understand RSA.
# Then link a integer index to password is a good way to start.
# You should not store password in code. So we use SHA256
# NOTE THAT YOU SHOULD NOT USE THIS IN PRODUCTION
# ETH AND RSA SIGN IS THE ONLY WAY TO BE SURE OF THE IDENTITY
# ANY SNIFFER CAN USE THE SHA256 PASSWORD TO CONNECT

sha256_to_index = {}
index_to_sha256_password = {}
bool_allow_sha256_password_connection = True
if bool_allow_sha256_password_connection:
    for line in unsecure_SHA256_password_connection.split("\n"):
        if len(line)>0:
            line= line.strip("\r").strip("\n").strip()
            index, password = line.split(":")
            index = index.strip().upper()
            password= password.strip().upper()
            index_to_sha256_password[index] = password.strip()
            sha256_to_index[password] = index.strip()
            print(f"In code Add SHA {index} {password[:8]}")
            


def is_message_signed(given_message):
    
    split_message = given_message.split("|")
    if len(split_message) < 3:
        return False
    message = split_message[0]
    address = split_message[1]
    signature = split_message[2]
    return is_message_signed_from_params(message, address, signature )

def is_message_signed_from_params(message, address, signature):
    # Message to verify

    # Encode the message
    encoded_message = encode_defunct(text=message)

    # Recover the address from the signature
    recovered_address = w3.eth.account.recover_message(encoded_message, signature=signature)
    return  recovered_address.lower() == address.lower()

def get_address_from_signed_message(given_message):
    split_message = given_message.split("|")
    if len(split_message) < 3:
        return None
    return split_message[1]


class UserHandshake:
    def __init__(self):
        self.index:int = 0
        self.address:str = ""
        self.handshake_guid:str = uuid.uuid4()
        self.remote_address:str = None          
        self.waiting_for_clipboard_sign_message:bool = False
        self.is_verified:bool = False       
        self.websocket= None       
        self.exit_handler=False
        
        
        
                
guid_handshake_to_valide_user = {}
index_handshake_to_valide_user_list = {}

bool_use_debug_print = True
def debug_print(text):
    if bool_use_debug_print:
        print(text)
        
        
async def hangle_text_message(user: UserHandshake, message: str):
    if not allow_text_message:
        await user.websocket.write_message(f"ONLY BYTE SERVER AND MAX:{int_max_byte_size}")
        await user.websocket.write_message(f"RTFM:{RTFM}")
        user.websocket.close()
        return
    if len(message) > int_max_char_size:
        await user.websocket.write_message(f"MAX TEXT SIZE {int_max_char_size}")
        await user.websocket.write_message(f"RTFM:{RTFM}")
        user.websocket.close()
        return
    print("Received text message", message)
    # if bool_use_as_listener_to:
    #     index = str(user.index)
    #     if index in index_handshake_to_valide_user_list:
    #         for user in index_handshake_to_valide_user_list[index]:
    #             if user.websocket is not None and not user.websocket.closed:
    #                 await user.io

broadcast_ip="127.0.0.1"
broadcast_port= [3615,4625]


byte_queue = queue.Queue()


def relay_iid_message_as_local_udp_thread(byte):
    print(f"Relay UDP {byte}")
    for port in broadcast_port:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(byte, ("127.0.0.1", port))
        sock.close()
        
def byte_to_send_in_queue_count():
    return byte_queue.qsize()

def pop_byte_from_queue():
    return byte_queue.get()

def flush_push_udp_queue():
    while byte_to_send_in_queue_count()>0:
        bytes = pop_byte_from_queue()
        print ("Flush one:", bytes)
        relay_iid_message_as_local_udp_thread(bytes)

async def push_byte_or_close( user: UserHandshake,  bytes: bytes):
    if user.websocket is None:
        return
    try:
        await user.websocket.write_message(bytes, binary=True)
    except tornado.websocket.WebSocketClosedError:
        print(f"WebSocketClosedError: Connection closed for user {user.index}")
        user.websocket.close()

"""
The IID send to be broadcaster to listeners is also send back to the sender.
(If the optoin of listener is on)
"""
bool_push_back_to_sender_bytes = True
async def append_byte_to_queue(user: UserHandshake,  byte_to_push:bytes):
    global byte_queue
    byte_queue.put(byte_to_push)

    if bool_use_as_listener_to:
        index = str(user.index)
        print(f"Push to index {index}")
        if index in index_handshake_to_valide_user_list:
            for user_in_list in index_handshake_to_valide_user_list[index]:
                if not bool_push_back_to_sender_bytes and user_in_list is user:
                    continue
                if user_in_list.websocket is not None and not user_in_list.websocket.close_code:
                        # tornado.ioloop.IOLoop.current().add_callback(push_byte_or_close,user, byte_to_push )
                        await push_byte_or_close(user_in_list, byte_to_push)
                else:
                    user_in_list.m_exit_handler=True
        

def is_ethereum_address(address):
    return address.startswith("0x") and len(address) == 42

def is_b58_rsa_address(address):
    return address.startswith("pBit4096B58Pkcs1SHA256")
    
    
def user_to_json(user):
                return json.dumps(user.__dict__, indent=4, default=str)  


def add_user_to_index(user: UserHandshake):
    index_str = str(user.index)
    if index_str not in index_handshake_to_valide_user_list:
        index_handshake_to_valide_user_list[index_str] = []
    index_handshake_to_valide_user_list[index_str].append(user)
    print (f"Add user to index {user.index} {len(index_handshake_to_valide_user_list[index_str])}")

def remove_user_from_index(user: UserHandshake):
    if user.index in index_handshake_to_valide_user_list:
        index_handshake_to_valide_user_list[user.index].remove(user)
        print (f"Remove user from index {user.index} {len(index_handshake_to_valide_user_list[user.index])}")

class WebSocketHandler(tornado.websocket.WebSocketHandler):
        def open(self):
            print("WebSocket opened")
            self.user = UserHandshake()
            self.user.websocket = self
            self.user.exit_handler=False
            self.user.handshake_guid = str(uuid.uuid4())
            self.write_message(f"SIGN:{self.user.handshake_guid}")
            self.user.waiting_for_clipboard_sign_message = True
            self.user.remote_address = self.request.remote_ip
            print (f"New connection from {self.user.remote_address}")
 
            print(user_to_json(self.user))
            

        async def on_message(self, message):
            global user_address_to_index
            global user_index_to_address

            print("T ", message)
            if self.user.waiting_for_clipboard_sign_message:
                if not isinstance(message, str):
                    print ("R", message)
                    return
                
                # SHA256:7074ce50c023524f306f63ed875fb9d244b606a54e0fae5e2f1d4d3359f59649
                if len(message)>7 and message.upper().strip().startswith("SHA256:"):
                    hash = message[7:].strip().upper()
                    print(sha256_to_index)
                    if hash in sha256_to_index:
                        index = sha256_to_index[hash]
                        self.user.index = int(index)
                        self.user.is_verified = True
                        guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                        if not bool_allow_guest_user and self.user.index < 0:
                            await self.write_message("GUEST DISABLED")
                            self.close()
                            return
                        self.user.waiting_for_clipboard_sign_message = False
                        self.user.address = hash
                        add_user_to_index(self.user)
                        string_callback = f"HELLO {index} {hash[:8]}..."
                        print(string_callback)
                        await self.write_message(string_callback)
                    else:
                        await self.write_message("INVALID SHA256:{hash}")
                        self.close()
                
                split_message = message.split("|")
                split_lenght = len(split_message)
                for i in range(split_lenght):
                    split_message[i] = split_message[i].strip()
                to_signed_guid = split_message[0]
                if split_lenght>1:
                    if not to_signed_guid.index(self.user.handshake_guid)==0:
                        print(f"GUID MISMATCH\n#{to_signed_guid}\n#{self.user.handshake_guid}")
                        await self.write_message("GUID MISMATCH")
                        self.close()
                
                        return

               

                if split_lenght == 3:
                    address = split_message[1].strip()
                    if is_verify_b58rsa4096_signature_no_letter_marque(to_signed_guid, message) and bool_allow_rsa_user:
                        
                        """
                        THE RSA ADDRESS IS VALIDE AND DONT USER LETTER MARQUE
                        THE SERVER IS SET TO ALLOW RSA ONLY USER
                        """
                        print(f"User {address} signed the handshake")
                        self.user.address = address
                        if address not in user_address_to_index:
                            await self.write_message("ASK ADMIN FOR A CLAIM TO BE ADDED (3)")
                            await self.write_message(f"RTFM:{RTFM}")
                            self.close()
                            return

                        self.user.index = int(user_address_to_index[address])
                        self.user.is_verified = True
                        guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                        if not bool_allow_guest_user and self.user.index < 0:
                            await self.write_message("GUEST DISABLED")
                            self.close()
                            return
                        self.user.waiting_for_clipboard_sign_message = False
                        add_user_to_index(self.user)
                        await self.write_message(f"HELLO {self.user.index} {self.user.address}")

                    elif is_ethereum_address(address):
                        """
                        CHECK IF THE ADDRESS IS A VALIDE ETHEREUM ADDRESS
                        """

                        print ("Try to log as admin")
                        print(f"Sign in message received: {message}")
                        if not is_message_signed(message):
                            await self.write_message("FAIL TO SIGN")
                            self.close()
                            return
                        address = get_address_from_signed_message(message)
                        print(f"User {address} signed the handshake")
                        self.user.address = address
                        if address not in user_address_to_index:
                            await self.write_message("ASK ADMIN FOR A CLAIM TO BE ADDED (1)")
                            await self.write_message(f"RTFM:{RTFM}")
                            self.close()
                            return
                        self.user.index = int(user_address_to_index[address])
                        self.user.is_verified = True
                        guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                        if not bool_allow_guest_user and self.user.index < 0:
                            await self.write_message("GUEST DISABLED")
                            self.close()
                            return
                        self.user.waiting_for_clipboard_sign_message = False
                        add_user_to_index(self.user)
                        await self.write_message(f"HELLO {self.user.index} {self.user.address}")

                elif split_lenght == 5 :
                    if is_verify_b58rsa4096_signature(to_signed_guid, message):
                        """
                        THE ADDRESS IS A RSA COASTER ADDRESS POINTING TO A ETHEREUM ADDRESS AND IS VALIDE
                        """
                        await self.write_message("VALIDE GUID SIGN IN")
                       
                        # 0:guid, 
                        # 1:coaster_address,
                        # 2:signature_by_coaster,
                        # 3:admin_address, 
                        # 4:signature_letter_maque
                        coaster_address = split_message[1].strip()
                        admin_address = split_message[3].strip()
                        signature_letter_maque = split_message[4].strip()
                    
                        if admin_address not in user_address_to_index:
                            await self.write_message("ASK ADMIN FOR A CLAIM TO BE ADDED(5)): "+admin_address)
                            await self.write_message(f"RTFM:{RTFM}")
                            self.close()
                            return

                        await self.write_message(f"COASTER SIGNED MASTER:{admin_address} COASTER:{coaster_address}")


                        self.user.address = admin_address
                        self.user.index = int(user_address_to_index[self.user.address])
                        self.user.is_verified = True
                        guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                        if not bool_allow_guest_user and self.user.index < 0:
                            await self.write_message("GUEST DISABLED")
                            self.close()
                            return
                        self.user.waiting_for_clipboard_sign_message = False
                        add_user_to_index(self.user)
                        await self.write_message(f"HELLO {self.user.index} {self.user.address} {coaster_address}")

                    elif split_lenght == 5:
                        """
                        CHECK IF THE COASTER USING AN ETHEREUM ADDRESS TO METAMASK IS VALIDE
                        """


                        print ("Try to log as coaster key")
                        # 0:guid, 
                        # 1:coaster_address,
                        # 2:signature_by_coaster,
                        # 3:admin_address, 
                        # 4:signature_letter_maque
                        coaster_address = split_message[1].strip()
                        signed_guid_by_coaster_address = split_message[2].strip()
                        admin_address = split_message[3].strip()
                        signature_letter_maque = split_message[4].strip()
                    
                        if admin_address not in user_address_to_index:
                            await self.write_message("ASK ADMIN FOR A CLAIM TO BE ADDED(6): "+admin_address)
                            await self.write_message(f"RTFM:{RTFM}")
                            self.close()
                            return

                        if not is_message_signed_from_params(coaster_address, admin_address, signature_letter_maque):
                            await self.write_message("LETTER MARQUE SIGNATURE INVALID")
                            self.close()
                            return
                        
                        if not is_message_signed_from_params(to_signed_guid, coaster_address, signed_guid_by_coaster_address):
                            await self.write_message("GUID NOT SIGNED BY COASTER")
                            self.close()
                            return
                        await self.write_message(f"COASTER SIGNED MASTER:{admin_address} COASTER:{coaster_address}")


                        self.user.address = admin_address
                        self.user.index = int(user_address_to_index[self.user.address])
                        self.user.is_verified = True
                        guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                        if not bool_allow_guest_user and self.user.index < 0:
                            await self.write_message("GUEST DISABLED")
                            self.close()
                            return
                        self.user.waiting_for_clipboard_sign_message = False
                        add_user_to_index(self.user)
                        await self.write_message(f"HELLO {self.user.index} {self.user.address} {coaster_address}")
            else:
                if self.user.exit_handler or self.user.websocket is None:
                    print("Exit handler")
                    remove_user_from_index(self.user)
                    return
                # print("Received message", message)
                if isinstance(message, str):
                    await hangle_text_message(self.user, message)
                else:
                    await handle_byte_message(self.user, message)

        def on_close(self):
            print("WebSocket closed")
            remove_user_from_index(self.user)

        def check_origin(self, origin):
            return True
    
def make_app():
    return tornado.web.Application([
        (r"/", WebSocketHandler),  # WebSocket endpoint
    ])    

async def handle_byte_message(user: UserHandshake, message: bytes):
        message_length = len(message)
        if message_length > int_max_byte_size:
            await user.websocket.write_message(f"MAX BYTE SIZE {int_max_byte_size}")
            await user.websocket.write_message(f"RTFM:{RTFM}")
            user.websocket.close()
            return

        if message_length == 4 or message_length == 8:
            current_time = int(get_ntp_time_from_local())
            int_value = 0
            if message_length == 4:
                int_value = struct.unpack('<i', message)[0]
            elif message_length == 8:
                int_index, int_value = struct.unpack('<ii', message)
            print(f"Relay {user.index} {int_value} {current_time}")
            
            await append_byte_to_queue(user,struct.pack('<iiQ', int(user.index), int_value, current_time))
            

        elif message_length == 12 or message_length == 16:
            ulong_date = 0
            int_value = 0
            if message_length == 12:
                int_value, ulong_date = struct.unpack('<iQ', message)
            elif message_length == 16:
                int_index, int_value, ulong_date = struct.unpack('<iiQ', message)
            print(f"Relay {user.index} {int_value} {ulong_date}")
            if bool_override_ntp_past_date:             
                server_ntp_time = int(get_ntp_time_from_local())
                if ulong_date <server_ntp_time:
                    ulong_date = int(server_ntp_time)

            await append_byte_to_queue(user,struct.pack('<iiQ', user.index, int_value, ulong_date))
            

def udp_async_server():
    import time
    int_debug_index=0
    while True:
        flush_push_udp_queue()
        int_debug_index+=1
        if int_debug_index>10000:
            print("-")
            int_debug_index=0
        time.sleep(0.0001)



        
def loop_udp_server():
  while True:
        try :
            asyncio.run(udp_async_server())
        except Exception as e:
            print (f"UDP PUSHER: {e}")
            traceback.print_exc()
        print ("Restarting PUSHER")
        

if __name__ == "__main__":
    
    def get_public_ip():
        response = requests.get('https://api.ipify.org?format=json')
        return response.json()['ip']

    public_ip = get_public_ip()
    print(f"Public IP: {public_ip}")
    
    server_thread = threading.Thread(target=udp_async_server)
    server_thread.daemon = True 
    server_thread.start()
    

    port_count = 4615
    while True:
        try:
            app = make_app()
            app.listen(port_count)  
            print(f"Server started on ws://0.0.0.0:{port_count}/")
            tornado.ioloop.IOLoop.current().start()
        except Exception as e:
            print (f"Server Port error: {e}")
            traceback.print_exc()
            port_count+=1
        
    
    


