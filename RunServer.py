# WARNING: IN THIS CODE I CONSIDER THAT YOU HAVE A SMALL COMMUNITY OF USERS
# THIS IS NOT DESIGN FOR A BIG COMMUNITY, ELSE YOU WILL NEED RUST CODE AND  FOLK

# https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python
# import iidwshandshake 

# pip install web3 eth-account base58 websockets requests tornado ntplib --break-system-packages 
# git clone https://github.com/EloiStree/2025_01_01_HelloMegaMaskPushToIID.git /git/push_iid


# DEFAULT TIP TO USER TO RUN SERVER
# NTP: raspberrypi.local
# Websocket: ws://raspberrypi.local:4615


import json
import socket
import time
import traceback
import uuid
import os
import asyncio
import struct
import requests
import queue
import threading
import tornado
import tornado.ioloop
import tornado.web
import tornado.websocket
import hashlib

from VerifyBit4096B58Pkcss1SHA256 import pBit4096B58Pkcs1SHA256
from typing import Dict



import sys

if sys.stdout.isatty():
    print("Running in a terminal.")
    stop_service_script ="""
    sudo systemctl stop apint_push_iid.service
    sudo systemctl stop apint_push_iid.timer
    """

    # run code to stop current service
    os.system(stop_service_script)

else:
    print("Not running in a terminal.")


# When you do some game you can trust user.
# This option override the NTP date with the server date if in the past.
bool_override_ntp_past_date=False


## No authentification needed.
## You better use this offline ^^.
bool_open_bar_mode=False
int_player_index_for_open_bar_mode=-42
## Would be better if I let's the user choose the id.
## But I don't have time for this code now (2025-03-21)

ntp_server = "be.pool.ntp.org"
ntp_server = "127.0.0.1"


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

relative_file_path_auth_eth = "Auth/ETH.txt"
relative_file_path_auth_sha256 = "Auth/SHA256.txt"
relative_file_path_auth_pBit4096B58Pkcs1SHA256 = "Auth/pBit4096B58Pkcs1SHA256.txt"
file_path_auth_git_eth_claimed_integer = "/git/apint_claims/whitelist_eth.txt"
file_path_auth_git_coaster_eth_claimed_integer = "/git/apint_claims/whitelist_coaster_eth.txt"
file_path_auth_git_coaster_rsa_claimed_integer = "/git/apint_claims/whitelist_coaster_rsa.txt"



def import_file_as_text(file_path, default_text):
    if not os.path.exists(file_path):
        
        ## create the folder
        folder = os.path.dirname(file_path)
        if not os.path.exists(folder):
            os.makedirs(folder)
        
        with open(file_path, 'w') as file:
            file.write(default_text)
    
    with open(file_path, 'r') as file:
        text = file.read()
        
    while " " in text:
        text = text.replace(" ", "")
    return text
    
def load_file_line_to_index_array(text, user_count_label=""):
    index_to_address_ref: Dict[str, str]={"":""}
    address_to_index_ref: Dict[str, str]={"":""}
    lines = text.split("\n")
    for line in lines:
        if ":" in line:
            t =line.split(":")
            if len(t)==2:
                index= t[0]
                address= t[1]
                index_to_address_ref[str(index)] = str(address.strip())
                address_to_index_ref[str(address)] = str(index.strip())
            
    print (f"Claimed {user_count_label} count: {len(index_to_address_ref)}")
    return index_to_address_ref, address_to_index_ref

def load_file_line_to_coaster_array(text):
    
    while " " in text:
        text = text.replace(" ", "")
    
    index_to_coaster_ref={}
    lines = text.split("\n")
    for line in lines:
        if ">" in line:
            address, coaster = line.split(">")
            index_to_coaster_ref[str(address.strip())] = str(coaster.strip())
    return index_to_coaster_ref

# -42 are shared keys for video guide and demonstration give by default publically

# If you are like 1-30 address, in code add could be usefull
# But you should prefer a file system if possible.
in_code_add_index_to_eth="""
 -42:0x9e85522e84c970431cEac4031Fbd2c24D8943527
""".replace(" ", "")

in_code_add_index_to_rsa4096="""
-42:pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9Qts8E6dKRN3JxwC1zGbSjVJzqygu6EtfHYaZbk5STKiuMwZgQ2fJqp5HQDFU3QX9ZkUR5PS62Zd4PHaj2AgCTNVRsFbAVemuQNSo5nqAko2MLjARPoV3j7avTcS7wmvA3L2ffCHfxskV46aqr8eKy5oNXmqoajscSiT1MF93aMUoSu6TqfgrkKUjUnUhAY37TcCCk7JjvPrapd8UeEnemKrf7as37R7Fi5stM7ngDi8mvQXfvY7fejvbDLuXf64H22UEzwVYgnerZG8A6SpaZW7hgAADFNZrUfyeybFrQFuYnH
"""

# 7074ce50c023524f306f63ed875fb9d244b606a54e0fae5e2f1d4d3359f59649 Patato 
# 6d61374da4b4df53c6f8fbf4c9b05576d647a07da7498b400abaf7e1f4f44124 Potato
in_code_add_index_to_sha256="""
# Generate Password: https://emn178.github.io/online-tools/sha256.html
-42:6d61374da4b4df53c6f8fbf4c9b05576d647a07da7498b400abaf7e1f4f44124
"""


text_index_to_eth = import_file_as_text(relative_file_path_auth_eth, in_code_add_index_to_eth)
text_index_to_rsa4096 = import_file_as_text(relative_file_path_auth_pBit4096B58Pkcs1SHA256, in_code_add_index_to_rsa4096)
text_index_to_sha256 = import_file_as_text(relative_file_path_auth_sha256, in_code_add_index_to_sha256)

text_index_to_eth_claim = import_file_as_text(file_path_auth_git_eth_claimed_integer, """
                                              # ADD IN THIS FILE THE ETHEREUM ADDRESS CLAIMED THAT YOUR AUTHORIZED
                                              # 
                                              # """)
text_index_to_coaster_eth_claim = import_file_as_text(file_path_auth_git_coaster_eth_claimed_integer, """
                                                      # ADD ETHEREUM WALLET THAT ARE ACTING AS COASTER AND THE MASTER WALLET
                                                      # https://eloistree.github.io/SignMetaMaskTextHere/index.html?q=guid_to_sign
                                                      """)
                                                      
# ADD ETHEREUM WALLET THAT ARE ACTING AS COASTER AND THE MASTER WALLET")
text_index_to_coaster_rsa_claim = import_file_as_text(file_path_auth_git_coaster_rsa_claimed_integer, """
                                                      # ADD RSA PUBLIC IN pBit4096B58Pkcs1SHA256 KEY THAT ARE ACTING AS COASTER AND THE MASTER WALLET
                                                      # https://eloistree.github.io/SignMetaMaskTextHere/index.html?q=guid_to_sign
                                                      # """)







## If false, the user with index < 0 will be rejected
# -integer index are key given to allow guest to use the server
bool_allow_guest_user = True

# Do you want to trust anyone with a signed message ?
bool_allow_unregistered_user = True

# Do you want to use RSA user without ethereum address ?
bool_allow_rsa_user = True

# Do you want to use SHA256 password to connect to the server ?
bool_allow_sha256_password_connection = True


# Array of allowed etherum address users allowed to connect
user_index_to_address,user_address_to_index  = load_file_line_to_index_array(text_index_to_eth, "Etherum Address")

# Array of allowed RSA4096 users allowed to connect
if bool_allow_rsa_user:
    user_index_to_rsa , user_rsa_to_index  = load_file_line_to_index_array(text_index_to_rsa4096, "RSA Public Key")
    
# Array of allowed SHA256 password users allowed to connect
if bool_allow_sha256_password_connection:
    user_index_to_sha256 , user_sha256_to_index  = load_file_line_to_index_array(text_index_to_sha256,"SHA256 Password")


git_index_to_eth_claimed_integer, git_eth_claimed_integer_to_index = load_file_line_to_index_array(text_index_to_eth_claim, "Etherum Address Claimed")
for index, value in git_index_to_eth_claimed_integer.items():
        user_index_to_address[str(index)] = str(value)
        user_address_to_index[str(value)] = str(index)
                
# ADDRESS >COASTER\n
git_index_to_coaster_eth = load_file_line_to_coaster_array(text_index_to_coaster_eth_claim)
git_index_to_coaster_rsa = load_file_line_to_coaster_array(text_index_to_coaster_rsa_claim)

print (f"Claimed Coaster Eth count: {len(git_index_to_coaster_eth)}")
print (f"Claimed Coaster RSA count: {len(git_index_to_coaster_rsa)}")



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
    global bool_open_bar_mode
    if bool_open_bar_mode:
        await user.websocket.write_message(f"OPEN BAR MODE: NO KICK BUT ONLY WE USE ONLY 16 BYTES LENGHT")
        return
       
    if not allow_text_message:
        await user.websocket.write_message(f"ONLY BYTE SERVER AND MAX:{int_max_byte_size}")
        await user.websocket.write_message(f"RTFM:{RTFM}")
        
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

async def push_byte_or_close( user: UserHandshake,  b: bytes):
    if user.websocket is None:
        return
    print(f"what {len(b)} ?{b}")
    try:
        await user.websocket.write_message(b, binary=True)
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
                
                print (user_in_list)
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
    index_str = str(user.index)
    if index_str in index_handshake_to_valide_user_list:
        if user in index_handshake_to_valide_user_list[index_str]:
            index_handshake_to_valide_user_list[index_str].remove(user)
            print(f"Remove user from index {user.index} {len(index_handshake_to_valide_user_list[index_str])}")
        if not index_handshake_to_valide_user_list[index_str]:  # Clean up empty lists
            del index_handshake_to_valide_user_list[index_str]

class WebSocketHandler(tornado.websocket.WebSocketHandler):
        async def open(self):
            print("WebSocket opened")
            self.user = UserHandshake()
            self.user.websocket = self
            self.user.exit_handler=False
            self.user.handshake_guid = str(uuid.uuid4())
            self.user.waiting_for_clipboard_sign_message = True
            self.user.remote_address = self.request.remote_ip
            
            if bool_open_bar_mode: 
                self.user.index = int_player_index_for_open_bar_mode
                self.user.is_verified = True
                self.user.waiting_for_clipboard_sign_message=False
                guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                add_user_to_index(self.user)
                await self.write_message(f"SERVER IS IN OPEN BAR MODE. HAVE FUN.")
                await self.write_message(f"HELLO {self.user.index}")
            else:
                await self.write_message(f"SIGN:{self.user.handshake_guid}")
            
            print (f"New connection from {self.user.remote_address}")
            print(user_to_json(self.user))

            
        def is_connection_lost(self):
            return self.user.exit_handler or self.user.websocket is None
            

        async def on_message(self, message):
            global user_address_to_index
            global user_index_to_address
            global user_index_to_rsa
            global user_rsa_to_index
            global user_index_to_sha256
            global user_sha256_to_index

        
            if self.user.waiting_for_clipboard_sign_message and not bool_open_bar_mode :
                if not isinstance(message, str):
                    return
                
                # SHA256:7074ce50c023524f306f63ed875fb9d244b606a54e0fae5e2f1d4d3359f59649
                if len(message)>7 and message.upper().strip().startswith("SHA256:"):
                    hash_recovered_password = str(message[7:].strip())
                    
                    bool_is_in = user_sha256_to_index.get(hash_recovered_password) is not None
                    if bool_is_in:
                        hash_recovered = hash_recovered_password
                        print(f"SHA256:{hash_recovered}")
                    else:
                        hash_recovered = pBit4096B58Pkcs1SHA256.get_password_sha256_hash(hash_recovered_password)
                        print(f"SHA256:{hash_recovered} {hash_recovered_password}")
                        bool_is_in = user_sha256_to_index.get(hash_recovered) is not None

                    if bool_is_in:
                        index = user_sha256_to_index[hash_recovered]
                        self.user.index = int(index)
                        self.user.is_verified = True
                        guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                        if not bool_allow_guest_user and self.user.index < 0:
                            await self.write_message("GUEST DISABLED")
                            self.close()
                            return
                        
                        self.user.waiting_for_clipboard_sign_message = False
                        self.user.address = hash_recovered
                        add_user_to_index(self.user)
                        string_callback = f"HELLO {index} {hash_recovered[:8]}..."
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

               
                if split_lenght == 0:
                    pass
                                
                elif split_lenght == 3 and pBit4096B58Pkcs1SHA256.is_signed_clipboard_ethereum_text(message):
                        """
                        CHECK IF THE ADDRESS IS A VALIDE ETHEREUM ADDRESS
                        """
                        address = pBit4096B58Pkcs1SHA256.get_address_from_clipboard_signed_message(message)
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
                elif split_lenght == 3:
                    address = split_message[1].strip()
                    if pBit4096B58Pkcs1SHA256.is_verify_b58rsa4096_signature_no_letter_marque(to_signed_guid, message) and bool_allow_rsa_user:
                        
                        """
                        THE RSA ADDRESS IS VALIDE AND DONT USER LETTER MARQUE
                        THE SERVER IS SET TO ALLOW RSA ONLY USER
                        """
                        print(f"User {address} signed the handshake")
                        self.user.address = address
                        if address not in user_rsa_to_index:
                            await self.write_message("ASK ADMIN FOR A CLAIM TO BE ADDED (3)")
                            await self.write_message(f"RTFM:{RTFM}")
                            self.close()
                            return

                        self.user.index = int(user_rsa_to_index[address])
                        self.user.is_verified = True
                        guid_handshake_to_valide_user[self.user.handshake_guid] = self.user
                        if not bool_allow_guest_user and self.user.index < 0:
                            await self.write_message("GUEST DISABLED")
                            self.close()
                            return
                        self.user.waiting_for_clipboard_sign_message = False
                        add_user_to_index(self.user)
                        await self.write_message(f"HELLO {self.user.index} {self.user.address}")


                elif split_lenght == 5 and pBit4096B58Pkcs1SHA256.is_verify_b58rsa4096_signature(to_signed_guid, message):
                        """
                        THE ADDRESS IS A RSA COASTER ADDRESS POINTING TO A ETHEREUM ADDRESS AND IS VALIDE
                        """
                       
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

                        await self.write_message(f"RSA COASTER SIGNED MASTER:{admin_address} COASTER:{coaster_address}")


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

                elif split_lenght == 5 and pBit4096B58Pkcs1SHA256.is_double_ethereum_letter_marque_handshake(to_signed_guid,message):
                        """
                        CHECK IF THE COASTER USING AN ETHEREUM ADDRESS TO METAMASK IS VALIDE
                        """

                        # 0:guid, 
                        # 1:coaster_address,
                        # 2:signature_by_coaster,
                        # 3:admin_address, 
                        # 4:signature_letter_maque

                        coaster_address = split_message[1].strip()
                        admin_address = split_message[3].strip()
                        await self.write_message(f"ECC COASTER SIGNED MASTER:{admin_address} COASTER:{coaster_address}")

                        self.user.address = admin_address
                        if not(self.user.address in user_address_to_index):
                            print(f"{user_address_to_index}")
                            print(f"Not in register:{admin_address}" )
                            await self.write_message(f"Not in allowed user")
                            self.close()
                            return
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
            current_time = int(get_local_timestamp_in_ms_utc_since1970())
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
        
    
    


