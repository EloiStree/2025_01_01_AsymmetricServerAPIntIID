# WARNING: IN THIS CODE I CONSIDER THAT YOU HAVE A SMALL COMMUNITY OF USERS
# THIS IS NOT DESIGN FOR A BIG COMMUNITY, ELSE YOU WILL NEED RUST CODE AND  FOLK




# https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python
# import iidwshandshake 

# 
# pip install web3 eth-account websockets requests tornado --break-system-packages 
# 
import json
import socket
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



w3 = Web3()
ntp_server = "time.google.com"

def get_ntp_time():
    import ntplib
    from time import ctime
    c = ntplib.NTPClient()
    response = c.request(ntp_server, version=3)
    return response.tx_time
def get_ntp_time_from_local():
    global millisecond_diff
    return asyncio.get_event_loop().time()*1000+millisecond_diff
ntp_timestmap = get_ntp_time()*1000
local_timestamp = asyncio.get_event_loop().time()*1000
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
"""

## If false, the user with index < 0 will be rejected
# -integer index are key given to allow guest to use the server
bool_allow_guest_user = True


# read the file
user_index_to_address={}
user_address_to_index={}

# if file exists
if True:
    with open(user_index_public_index_file, 'r') as file:
        text = file.read()
        lines = text.split("\n")
        for line in lines[:20]:
            if ":" in line:
                index, address = line.split(":")
                user_index_to_address[index] = address
                user_address_to_index[address] = index
                
print (f"Claimed index: {len(user_index_to_address)}")
dict_size = sys.getsizeof(user_index_to_address)
for key, value in user_index_to_address.items():
    dict_size += sys.getsizeof(key) + sys.getsizeof(value)
dico_size_in_mo = int(int(dict_size) / 1024 / 1024*10000) / 10000
print(f"Byte size of user_index_to_address: {dict_size}, {dico_size_in_mo} Mo")

for line in additionnal_in_code_add.split("\n"):
    if len(line)>0:
        index, address = line.split(":")
        user_index_to_address[index] = address
        user_address_to_index[address] = index
        print(f"In code Add {index} {address}")




    


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

async def append_byte_to_queue(user: UserHandshake,  byte_to_push:bytes):
    global byte_queue
    byte_queue.put(byte_to_push)

    if bool_use_as_listener_to:
        index = str(user.index)
        print(f"Push to index {index}")
        if index in index_handshake_to_valide_user_list:
            for user_in_list in index_handshake_to_valide_user_list[index]:
                if user_in_list is not user:
                    if user_in_list.websocket is not None and not user_in_list.websocket.close_code:
                        tornado.ioloop.IOLoop.current().add_callback(user_in_list.websocket.write_message, byte_to_push, binary=True)
        
    
    
    
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
            self.user.handshake_guid = str(uuid.uuid4())
            self.write_message(f"SIGN:{self.user.handshake_guid}")
            self.user.waiting_for_clipboard_sign_message = True
            self.user.remote_address = self.request.remote_ip
            print (f"New connection from {self.user.remote_address}")
 
            print(user_to_json(self.user))
            

        async def on_message(self, message):
            
            print("T ", message)
            if self.user.waiting_for_clipboard_sign_message:
                if not isinstance(message, str):
                    print ("R", message)
                    return
                split_message = message.split("|")
                split_lenght = len(split_message)
                for i in range(split_lenght):
                    split_message[i] = split_message[i].strip()
                to_signed_guid = split_message[0]
                if split_lenght>1:
                    if not to_signed_guid.index(self.user.handshake_guid)==0:
                        print(f"GUID MISMATCH\n#{to_signed_guid}\n#{self.user.handshake_guid}")
                        await self.write_message("GUID MISMATCH")
                        return
                    
                if split_lenght == 3:
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
                        await self.write_message("ASK ADMIN FOR A CLAIM TO BE ADDED")
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
                if split_lenght == 5:
                    print ("Try to log as coaster key")
                    # 0:guid, 
                    # 1:coaster_address,
                    # 2:signature_by_coaster,
                    # 3:admin_address, 
                    # 4:signature_letter_maque
                    coaster_address = split_message[1]
                    signed_guid_by_coaster_address = split_message[2]
                    admin_address = split_message[3]
                    signature_letter_maque = split_message[4]
                
                    if admin_address not in user_address_to_index:
                        await self.write_message("ASK ADMIN FOR A CLAIM TO BE ADDED: "+admin_address)
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
            print("A")

        elif message_length == 12 or message_length == 16:
            ulong_date = 0
            int_value = 0
            if message_length == 12:
                int_value, ulong_date = struct.unpack('<iQ', message)
            elif message_length == 16:
                int_index, int_value, ulong_date = struct.unpack('<iiQ', message)
            print(f"Relay {user.index} {int_value} {ulong_date}")
            await append_byte_to_queue(user,struct.pack('<iiQ', user.index, int_value, ulong_date))
            print("A")

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
    
    app = make_app()
    app.listen(4615)  
    print("Server started on ws://0.0.0.0:4615/")
    tornado.ioloop.IOLoop.current().start()
 
    
    


