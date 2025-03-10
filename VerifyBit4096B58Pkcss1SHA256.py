# pip install base58 web3 cryptography --break-system-packages

"""
sudo apt update
sudo apt install libssl1.1

"""

from web3 import Web3
import os
from eth_account.messages import encode_defunct
import uuid
import os

# pip install base58
import base64
import base58


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend



import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from xml.etree import ElementTree
w3 = Web3()




start_public_key_b58 = "pBit4096B58Pkcs1SHA256"
start_private_key_b58 = "PBit4096B58Pkcs1SHA256"



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




def parse_rsa_key(xml_string):
    root = ElementTree.fromstring(xml_string)
    modulus = int(base64.b64decode(root.find('Modulus').text).hex(), 16)
    exponent = int(base64.b64decode(root.find('Exponent').text).hex(), 16)
    d = int(base64.b64decode(root.find('D').text).hex(), 16)
    p = int(base64.b64decode(root.find('P').text).hex(), 16)
    q = int(base64.b64decode(root.find('Q').text).hex(), 16)
    dp = int(base64.b64decode(root.find('DP').text).hex(), 16)
    dq = int(base64.b64decode(root.find('DQ').text).hex(), 16)
    inverse_q = int(base64.b64decode(root.find('InverseQ').text).hex(), 16)

    private_key = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=inverse_q,
        public_numbers=rsa.RSAPublicNumbers(e=exponent, n=modulus)
    ).private_key()

    return private_key

def parse_rsa_public_key(xml_string):
    # Parse the XML string
    root = ElementTree.fromstring(xml_string)
    
    # Extract the Modulus and Exponent, decode from Base64, and convert to integers
    modulus = int(base64.b64decode(root.find('Modulus').text).hex(), 16)
    exponent = int(base64.b64decode(root.find('Exponent').text).hex(), 16)
    
    # Create an RSA public key
    public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    return public_key

def  check_signature(public_key_object, signature, message):
    try:
        public_key_object.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False
    


def is_verify_b58rsa4096_signature_no_letter_marque(guid_sent, received_guid_handshake):
    guid_sent =   guid_sent.strip()
    received_guid_handshake = received_guid_handshake.strip()
    if not received_guid_handshake.startswith(guid_sent):
        print("Error: GUID does not match")
        return False
    if received_guid_handshake.index("|") <0:
        print("Error: Not a clipboard handshake")
        return False


    hankshake_splits = received_guid_handshake.split("|")
    handshake_splits_lenght = len(hankshake_splits)

    if not handshake_splits_lenght == 3:
        print("Error: Handshake must be direct 3 tokens")
        return False

    print("Token Lenght: ", handshake_splits_lenght)
     
    received_public_address = hankshake_splits[1].strip()

    bool_is_ethereum_address = received_public_address.startswith("0x")
    if bool_is_ethereum_address:
        print ("Ethereum Address: ", received_public_address)
        print ("Let's focus on RSA.")
        return False


    bool_is_b58Rsa_address= received_public_address.startswith("pBit4096B58Pkcs1SHA256")
    if not bool_is_b58Rsa_address:
        print ("Error: Not a RSA address")
        return False

        
    print ("Is B58 RSA Address: ", bool_is_b58Rsa_address)

    if handshake_splits_lenght >=1:
        received_guid_handshake = hankshake_splits[0].strip()
    if handshake_splits_lenght >=3:
        received_signature = hankshake_splits[2].strip()

    print(">> Received Handshake")
    print("Guid: ", received_guid_handshake)
    print("Public Address: ", received_public_address)
    print("Signature: ", received_signature)

    guid_clipboard= f"{received_guid_handshake}|{received_public_address}|{received_signature}"

    print(">> Clipboard ")
    print ("Sign Message: ", guid_clipboard)

    print(">> Parse Base 58 to public key pem")
    public_key_as_b58 = received_public_address[len(start_public_key_b58):]

    print("Public key as XML")
    decoded_public_key = base58.b58decode(public_key_as_b58).decode('utf-8')

    print(decoded_public_key)

    print("\n--------------\n")

    public_key_object = parse_rsa_public_key(decoded_public_key)

    # # Serialize the key to PEM format (optional)
    # pem = public_key_object.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # )

    # print(pem.decode('utf-8'))

    # print("-------------------------------------")

    print(">> Is message signed as B58")
    signature_bytes = base58.b58decode(received_signature)
    print("Signature Bytes: ", signature_bytes)




    bool_is_guid_signed = check_signature(public_key_object, signature_bytes, received_guid_handshake.encode('utf-8'))

    print(">> Is message signed")
    print("Is Guid Signed: ", bool_is_guid_signed)

    return bool_is_guid_signed

def is_verify_b58rsa4096_signature(guid_sent, received_guid_handshake):

    guid_sent =   guid_sent.strip()
    received_guid_handshake = received_guid_handshake.strip()


    # guid_sent ="""

    # 68e5616a-6066-4acc-b349-b7b2a6d3eff8

    # """.strip()
    # received_guid_handshake = """

# MESSAGETOSIGNE
# PUBLICADDRESS
# SIGNATURE
# MASTERADDRESS
# MASTERSIGNATURE


    # 68e5616a-6066-4acc-b349-b7b2a6d3eff8|
    # pBit4096B58Pkcs1SHA2568arQkFZ8ZJYKVVkCiefn9ckvmUDmF9Hy5YEoNn4FoJn61B7bP9fFwYxWMGQpZJAD2374pnfxqaj5aThoR2j5SJk8TpScHwGThbJkfwDogkVoW523YTxP69LiZkE92qcgsrcSYZfkoqFtyFXVVkN9m5o3SDNNy2pSN9eygZGvvGigJMkXGb8xREGAmvkPt8XV79UbxvoooN1HaTRJu6LwiTJ41zFrGfyZnxMVgeRsxa3brrTpYoxt2hvh1otJ3HxajWeFfvqysYadKzoC1u54C7AuZPCpSkUbzEgERDLC5f5fqJ8LTdcTsubrC5BFQZQK6YBGN3PycYEy|
    # FocHa7Q8kknGi4XZt4snBQ3zfXxJ4ZQE7vipVYbFmMF9iTwmrob1UHZbcPx2qDSH3zj9WDEjBbSn8wkBAdPtCsgA3SL7ZEVFNRJrdF4K2cq1izTEESNnaP9AkghjhtATXq6kDc5qmiqrcggM72MRzwzbekgVYXDbifv7VTzkcGWuvQT|
    # 0xDa3239C8ad5C321A1411F3acC2C1f9F8C9D34ECE|
    # 0x86644c8831bd3b4c876fcf72d41604d40636d78681acd3756e83b54f267365c558a10b401f5ef797fce02b0a8d6b2a69a8ee79b9607b15eda7c7e88c25c80d2a1b
    # """.strip()


    if not received_guid_handshake.startswith(guid_sent):
        print("Error: GUID does not match")
        return False
        
    if received_guid_handshake.index("|") <0:
        print("Error: Not a clipboard handshake")
        return False

    hankshake_splits = received_guid_handshake.split("|")
    handshake_splits_lenght = len(hankshake_splits)

    print("Token Lenght: ", handshake_splits_lenght)

    if not (handshake_splits_lenght == 3 or  handshake_splits_lenght == 5):
        print("Error: Handshake must be direct 3 tokens or by coaster 5 tokens")
        return False
        
        
    received_public_address = hankshake_splits[1].strip()


    start_public_key_b58 = "pBit4096B58Pkcs1SHA256"
    start_private_key_b58 = "PBit4096B58Pkcs1SHA256"


    bool_is_ethereum_address = received_public_address.startswith("0x")
    if bool_is_ethereum_address:
        print ("Ethereum Address: ", received_public_address)
        print ("Let's focus on RSA.")
        return False


    bool_is_b58Rsa_address= received_public_address.startswith("pBit4096B58Pkcs1SHA256")
    if handshake_splits_lenght == 3:
        print ("Error: RSA need letter marque to exist on server")
        print ("Or added/override by the admin to an index")
        return False
        
    print ("Is Ethereum Address: ", bool_is_ethereum_address)
    print ("Is B58 RSA Address: ", bool_is_b58Rsa_address)



    if handshake_splits_lenght >=1:
        received_guid_handshake = hankshake_splits[0].strip()
    if handshake_splits_lenght >=3:
        received_signature = hankshake_splits[2].strip()
    if handshake_splits_lenght >=4:
        received_master_address = hankshake_splits[3].strip()
    if handshake_splits_lenght >=5:
        received_master_signature = hankshake_splits[4].strip()

    print(">> Received Handshake")
    print("Guid: ", received_guid_handshake)
    print("Public Address: ", received_public_address)
    print("Signature: ", received_signature)
    print("Master Address: ", received_master_address)
    print("Master Signature: ", received_master_signature)



    letter_marque_clipboard = f"{received_public_address}|{received_master_address}|{received_master_signature}"
    guid_clipboard= f"{received_guid_handshake}|{received_public_address}|{received_signature}"

    print(">> Clipboard ")
    print ("Letter Marque: ", letter_marque_clipboard)
    print ("Sign Message: ", guid_clipboard)


    print(">> Recover XML RSA key.")
    print("Bit: 4096")
    print("Encoding: base58")
    print("Hash: SHA256")
    print("Padding: PKCS1")
    print("")

    print(">> Is letter mask valide")


    print(">> Letter Marque")
    print("Message: ", received_public_address)
    print("Address: ", received_master_address)
    print("Signature: ", received_master_signature)

    print("")
    bool_is_letter_marque_signed = is_message_signed_from_params(received_public_address, received_master_address, received_master_signature)
    print("Is Letter Maque valide:", bool_is_letter_marque_signed)
    print()
    print("")

    if not bool_is_letter_marque_signed:
        print("Error: Letter Marque is not signed.")
        return False






    print(">> Parse Base 58 to public key pem")
    public_key_as_b58 = received_public_address[len(start_public_key_b58):]

    print("Public key as XML")
    decoded_public_key = base58.b58decode(public_key_as_b58).decode('utf-8')

    print(decoded_public_key)



    print("\n--------------\n")






    public_key_object = parse_rsa_public_key(decoded_public_key)

    # Serialize the key to PEM format (optional)
    pem = public_key_object.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print(pem.decode('utf-8'))

    print("-------------------------------------")

    print(">> Is message signed as B58")
    signature_bytes = base58.b58decode(received_signature)
    print("Signature Bytes: ", signature_bytes)




    bool_is_guid_signed = check_signature(public_key_object, signature_bytes, received_guid_handshake.encode('utf-8'))

    print(">> Is message signed")
    print("Is Guid Signed: ", bool_is_guid_signed)

    return bool_is_guid_signed


