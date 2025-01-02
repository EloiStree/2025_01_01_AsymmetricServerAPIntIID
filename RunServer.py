# WARNING: IN THIS CODE I CONSIDER THAT YOU HAVE A SMALL COMMUNITY OF USERS
# THIS IS NOT DESIGN FOR A BIG COMMUNITY, ELSE YOU WILL NEED RUST CODE AND  FOLK


#import iidwshandshake # https://github.com/EloiStree/2025_01_01_MegaMaskSignInHandshake_Python/tree/main

# pip install web3
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
import time
import queue

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
    return time.time()*1000+millisecond_diff
ntp_timestmap = get_ntp_time()*1000
local_timestamp = time.time()*1000
millisecond_diff = ntp_timestmap-local_timestamp
print(f"ntp_timestmap: {ntp_timestmap}")
print(f"local_timestamp: {local_timestamp}")
print(f"diff: {millisecond_diff}")



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




bool_use_byte_count = True
byte_count_ip="127.0.0.1"
byte_count_port=666
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
byte_count_target=  (byte_count_ip, byte_count_port)

async def byte_count(index_integer:int, byte_count:int):
    byte = struct.pack('<ii', index_integer, byte_count)
    sock.sendto(byte, byte_count_target)
    
    


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
        
        
bool_only_byte_server = False
int_max_byte_size = 16
async def hangle_text_message(user:UserHandshake, message:str):
    if not bool_only_byte_server:
        user.websocket.send(f"ONLY BYTE SERVER AND MAX:{int_max_byte_size}")
        user.websocket.send(f"RTFM:{RTFM}") 
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
        
    
        
    
async def handle_byte_message(user:UserHandshake, message:bytes):
    message_length = len(message)
    if message_length> int_max_byte_size:
        user.websocket.send(f"MAX BYE SIZE {int_max_byte_size}")
        user.websocket.send(f"RTFM:{RTFM}") 
        user.websocket.close()
        return
    
    if message_length == 4 or message_length == 8:
        current_time =int( get_ntp_time_from_local() )
        int_value =0
        if message_length == 4:
            int_value = struct.unpack('<i', message)[0]
        elif message_length == 8:
            int_index, int_value = struct.unpack('<ii', message)[0]
        print(f"Relay {user.index} {int_value} {current_time}")
        await append_byte_to_queue(struct.pack('<iiQ', int(user.index), int_value, current_time))
        print("A")
        
    elif message_length == 12 or message_length == 16:
        ulong_date =0
        int_value =0
        if message_length == 12:
            int_value, ulong_date = struct.unpack('<iQ', message)[0]
        elif message_length == 16:
            int_index, int_value, ulong_date = struct.unpack('<iiQ', message)[0]
        print(f"Relay {user.index} {int_value} {ulong_date}")
        await append_byte_to_queue(struct.pack('<iiQ', user.index, int_value, ulong_date))
        print("A")
        
async def handle_connection(websocket, path):
    debug_print(f"New connection from path {path}")
    debug_print(f"New connection from address {websocket.remote_address}")
    user : UserHandshake = UserHandshake()
    user.remote_address = websocket.remote_address    
    user.websocket= websocket
    await websocket.send(f"MANUAL:{RTFM}")
    await websocket.send(f"SIGN:{user.handshake_guid}")
    user.waiting_for_clipboard_sign_message = True
    
    try:
        while True:   
            print("--C-")
            async for message in websocket:
                print("--B START-")
                if user.waiting_for_clipboard_sign_message:
                    if not is_message_signed(message):
                        await websocket.send(f"FAIL TO SIGN")
                        await websocket.close()
                    address = get_address_from_signed_message(message)
                    print (f"User {user.address} signed the handshake")
                   
                    user.address = address
                    if address not in user_address_to_index:
                        await websocket.send(f"ASK ADMIN FOR A CLAIM TO BE ADDED")
                        await websocket.send(f"RTFM:{RTFM}")
                        await websocket.close()
                    user.index =int( user_address_to_index[address])
                    user.is_verified = True
                    user.waiting_for_clipboard_sign_message = False
                    guid_handshake[user.handshake_guid] = user
                    
                    if not bool_allow_guest_user and user.index <0:
                        await websocket.send(f"GUEST DISABLED")
                        await websocket.close()
                    await websocket.send(f"HELLO {user.index} {user.address}")
                else:
                    print("Received message", message)
                    # if isinstance(message, str):
                    #     await hangle_text_message(user, message)
                    # else:
                    #     await handle_byte_message(user, message)
                    ## ADD LATER
                    # if bool_use_byte_count:
                    #     byte_count(int(user.index), len(message))
                
                print("--B END-")
                    
    except websockets.ConnectionClosed:
        print(f"Connection closed from {websocket.remote_address}")


async def main():
    server = await websockets.serve(handle_connection, "0.0.0.0", 4615)
    print("WebSocket server started on ws://0.0.0.0:4615")
    await server.wait_closed()



    
import threading


def loop_websocket_server():
    while True:
        try :
            asyncio.run(main())
        except Exception as e:
            print (f"Error in websocket server: {e}")
            traceback.print_exc()
        print ("Restarting websocket server")
        time.sleep(5)
        
def loop_udp_server():
    while True:
        flush_push_udp_queue()
        print("-")
        time.sleep(1)


if __name__ == "__main__":
    
    def get_public_ip():
        response = requests.get('https://api.ipify.org?format=json')
        return response.json()['ip']

    public_ip = get_public_ip()
    print(f"Public IP: {public_ip}")
    
    thread1= threading.Thread(target=loop_websocket_server)
    thread2= threading.Thread(target=loop_udp_server)
    thread1.start()
    thread2.start()
    
    thread1.join()
    thread2.join()


