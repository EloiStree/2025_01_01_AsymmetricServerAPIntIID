# WARNING: IN THIS CODE I CONSIDER THAT YOU HAVE A SMALL COMMUNITY OF USERS
# THIS IS NOT DESIGN FOR A BIG COMMUNITY, ELSE YOU WILL NEED RUST CODE AND  FOLK


#import iidwshandshake # https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python/tree/main

# pip install web3
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




RTFM= "https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python.git"

print("Hello World Python IID Listen Server")
user_index_public_index_file = "/git/APIntIO_Claim/Claims"

bool_allow_guest_user = True

# read the file
user_index_to_address={}
user_address_to_index={}

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
        self.index:int = index
        self.address:str = address
        self.handshake_guid:str = uuid.uuid4()
        self.remote_address:str = None          
        self.waiting_for_clipboard_sign_message:bool = False
        self.is_verified:bool = False       
        self.websocket= None       
        
        
        
                
guid_handshake = {}

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

async def append_byte_to_queue(byte):
    global byte_queue
    byte_queue.put(byte)
        
    
    
    
def user_to_json(user):
                return json.dumps(user.__dict__, indent=4, default=str)  
    
class WebSocketHandler(tornado.websocket.WebSocketHandler):
        def open(self):
            print("WebSocket opened")
            self.user = UserHandshake()
            self.user.websocket = self
            self.user.handshake_guid = uuid.uuid4()
            self.write_message(f"SIGN:{self.user.handshake_guid}")
            self.user.waiting_for_clipboard_sign_message = True
            self.user.remote_address = self.request.remote_ip
            print (f"New connection from {self.user.remote_address}")
 
            print(user_to_json(self.user))
            

        async def on_message(self, message):
            
            if self.user.waiting_for_clipboard_sign_message:
                if not isinstance(message, str):
                    print ("R", message)
                    return
                
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
                guid_handshake[self.user.handshake_guid] = self.user
                if not bool_allow_guest_user and self.user.index < 0:
                    await self.write_message("GUEST DISABLED")
                    self.close()
                    return
                self.user.waiting_for_clipboard_sign_message = False
                await self.write_message(f"HELLO {self.user.index} {self.user.address}")
            else:
                # print("Received message", message)
                if isinstance(message, str):
                    await hangle_text_message(self.user, message)
                else:
                    await handle_byte_message(self.user, message)

        def on_close(self):
            print("WebSocket closed")

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
            await append_byte_to_queue(struct.pack('<iiQ', int(user.index), int_value, current_time))
            print("A")

        elif message_length == 12 or message_length == 16:
            ulong_date = 0
            int_value = 0
            if message_length == 12:
                int_value, ulong_date = struct.unpack('<iQ', message)
            elif message_length == 16:
                int_index, int_value, ulong_date = struct.unpack('<iiQ', message)
            print(f"Relay {user.index} {int_value} {ulong_date}")
            await append_byte_to_queue(struct.pack('<iiQ', user.index, int_value, ulong_date))
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
 
    
    


