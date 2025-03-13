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

import hashlib

class pBit4096B58Pkcs1SHA256:
    start_public_key_b58 = "pBit4096B58Pkcs1SHA256"
    start_private_key_b58 = "PBit4096B58Pkcs1SHA256"
    bool_use_debug_log=True
    
    def debug_log(message):
        if pBit4096B58Pkcs1SHA256.bool_use_debug_log:
            print(message)
            
    def __init__(self):
        pass


    def get_password_sha256_hash(password):
        """
        Check if a password is the same as the stored hash
        """
        sha256_hash = hashlib.sha256()
        sha256_hash.update(password.encode())
        hash_recovered = sha256_hash.hexdigest()
        
        return hash_recovered

    def is_signed_clipboard_ethereum_text(given_message):
        """
        return True if the Message|Address|Signature format and the signature is valid
        """
        
        split_message = given_message.split("|")
        if len(split_message) < 3:
            return False
        message = split_message[0]
        address = split_message[1]
        signature = split_message[2]
        return pBit4096B58Pkcs1SHA256.is_signed_clipboard_ethereum_text_as_three_params(message, address, signature )

    def is_signed_clipboard_ethereum_text_as_three_params(message, address, signature):
        """
        return True if the Message|Address|Signature format and the signature is valid
        """
        
        if not message or not address or not signature:
            return False
        if not address.startswith("0x"):
            return False
    

        # Encode the message
        encoded_message = encode_defunct(text=message)

        # Recover the address from the signature
        recovered_address = w3.eth.account.recover_message(encoded_message, signature=signature)
        return  recovered_address.lower() == address.lower()

    def get_address_from_clipboard_signed_message(given_message):
        split_message = given_message.split("|")
        if len(split_message) < 3:
            return None
        return split_message[1]


    def parse_rsa_key(xml_string):
        """
        Parse a RSA Key from an XML produced in Unity3D C# to a object in python.
        """
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
        """
         Parse a RSA Public Key from an XML produced in Unity3D C# to a object in python.
        """
        root = ElementTree.fromstring(xml_string)
        
        # Extract the Modulus and Exponent, decode from Base64, and convert to integers
        modulus = int(base64.b64decode(root.find('Modulus').text).hex(), 16)
        exponent = int(base64.b64decode(root.find('Exponent').text).hex(), 16)
        
        # Create an RSA public key
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        return public_key

    def  check_signature_public_key_rsa(public_key_object, signature, message):
        
        """Given a public key oject a signature and a message, verify if the signature is valid"""
        
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
        """Full process of verifying a clipboard handshakein the 
        format of Guid|PublicAddress|Signature
        It need the sent message to sign (guid here) and the received message. 
        """
        
        ## Let's check if the received message is the same as the sent message.
        guid_sent =   guid_sent.strip()
        received_guid_handshake = received_guid_handshake.strip()
        if not received_guid_handshake.startswith(guid_sent):
            ## Apparently ti was notthe same so we can leave.
            pBit4096B58Pkcs1SHA256.debug_log("Error: GUID does not match")
            return False
        ## Let's check if the received signature ahve | in it.
        if received_guid_handshake.index("|") <0:
            ## Apparently it has not | in it so we can leave.
            pBit4096B58Pkcs1SHA256.debug_log("Error: Not a clipboard handshake")
            return False


        hankshake_splits = received_guid_handshake.split("|")
        handshake_splits_lenght = len(hankshake_splits)

        ## If we don't have 3 pieces, the format is not the right one.
        if not ( handshake_splits_lenght == 3 or handshake_splits_lenght == 5):
            # Apparently it is not a 3 pieces handshake. Let's leave.
            pBit4096B58Pkcs1SHA256.debug_log("Error: Handshake must be direct 3 or 5 tokens")
            return False

        ## Let's isolate the public address of the possible RSA key.
        received_public_address = hankshake_splits[1].strip()

        ## If we are in a ehthereum address, we can leave.
        bool_is_ethereum_address = received_public_address.startswith("0x")
        if bool_is_ethereum_address:
            ## Apparently it is an ethereum address, let's leave.
            pBit4096B58Pkcs1SHA256.debug_log ("Ethereum Address: ", received_public_address)
            return False

        ## All the pBitRSA that are public start with pBit4096B58Pkcs1SHA256
        bool_is_b58Rsa_address= received_public_address.startswith(pBit4096B58Pkcs1SHA256.start_public_key_b58)
        if not bool_is_b58Rsa_address:
            ## And apparently it is not starting witht the tag, let's leave.
            pBit4096B58Pkcs1SHA256.debug_log ("Error: Not a RSA address")
            return False

            
        pBit4096B58Pkcs1SHA256.debug_log ("Is B58 RSA Address: "+str(bool_is_b58Rsa_address))

        ## Let's isolate the guid from the received message to process them
        received_guid_handshake = hankshake_splits[0].strip()
        received_signature = hankshake_splits[2].strip()
        guid_clipboard= f"{received_guid_handshake}|{received_public_address}|{received_signature}"

        # Display for debug: the received message
        pBit4096B58Pkcs1SHA256.debug_log(">> Received Handshake")
        pBit4096B58Pkcs1SHA256.debug_log("Guid: "+ str(received_guid_handshake))
        pBit4096B58Pkcs1SHA256.debug_log("Public Address: "+ str(received_public_address))
        pBit4096B58Pkcs1SHA256.debug_log("Signature: "+ str(received_signature))
        pBit4096B58Pkcs1SHA256.debug_log(">> Clipboard ")
        pBit4096B58Pkcs1SHA256.debug_log ("Sign Message: "+ str(guid_clipboard))
        pBit4096B58Pkcs1SHA256.debug_log(">> Parse Base 58 to public key pem")
        
        ## Let's extract the front tag of the RSA key in B58
        public_key_as_b58 = received_public_address[len(pBit4096B58Pkcs1SHA256.start_public_key_b58):]

        ## Let's decode the B58 to get the XML of the RSA key
        decoded_public_key = base58.b58decode(public_key_as_b58).decode('utf-8')


        pBit4096B58Pkcs1SHA256.debug_log(f"XML FOUND:{decoded_public_key}")
        pBit4096B58Pkcs1SHA256.debug_log("\n--------------\n")

        ## To use the utility we need an python object of the public key
        public_key_object = pBit4096B58Pkcs1SHA256.parse_rsa_public_key(decoded_public_key)

        ## For the fun let's display the public key in PEM format of it.
        if pBit4096B58Pkcs1SHA256.bool_use_debug_log:
            pem =pBit4096B58Pkcs1SHA256.turn_public_key_object_to_pem_text(public_key_object)
            pBit4096B58Pkcs1SHA256.debug_log(f"PEM:{pem}")
       

        pBit4096B58Pkcs1SHA256.debug_log(">> Is message signed as B58")
        ## To verify the signature we need to use it binary format
        signature_bytes = base58.b58decode(received_signature)
        pBit4096B58Pkcs1SHA256.debug_log(f"Signature Bytes:{signature_bytes}")
        bool_is_guid_signed = pBit4096B58Pkcs1SHA256.check_signature_public_key_rsa(public_key_object, signature_bytes, received_guid_handshake.encode('utf-8'))

        pBit4096B58Pkcs1SHA256.debug_log(">> Is message signed")
        pBit4096B58Pkcs1SHA256.debug_log(f"Is Guid Signed: { bool_is_guid_signed}")
        ## Let's return the result of the verification
        return bool_is_guid_signed
    
    def turn_public_key_object_to_pem_text(public_key_object):
        """
        This function will turn a public key object to a PEM text format (use in the Web3 community)
        """
        
        # Serialize the key to PEM format (optional)
        pem = public_key_object.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def print_debug_pbit_info():
        pBit4096B58Pkcs1SHA256.debug_log(">> Recover XML RSA key.")
        pBit4096B58Pkcs1SHA256.debug_log("Bit: 4096")
        pBit4096B58Pkcs1SHA256.debug_log("Encoding: base58")
        pBit4096B58Pkcs1SHA256.debug_log("Hash: SHA256")
        pBit4096B58Pkcs1SHA256.debug_log("Padding: PKCS1")
        pBit4096B58Pkcs1SHA256.debug_log("")
        
    def is_verify_b58rsa4096_signature(guid_sent, received_guid_handshake):

        ## If it is not a valie RSA signature on the first 3 arguments, we can leave.
        bool_valide_rsa_signature = pBit4096B58Pkcs1SHA256.is_verify_b58rsa4096_signature_no_letter_marque(guid_sent, received_guid_handshake)
        if not bool_valide_rsa_signature:
            ## Apparently the RSA signature is allready not valide, let's leave.
            return False    
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
        
        
        # All we need to do as the handshake is validated on the RSA key,
        # is to verify the Ethereum account authorized to use the RSA key in his name.

        # Letter Marque handshake is compose of 5 pieces, let's count them.
        hankshake_splits = received_guid_handshake.split("|")
        if hankshake_splits!=5:
            # Apparently it is not a 5 pieces handshake. Let's leave.
            return False
        rsa_pbit_key = hankshake_splits[1].strip()
        received_master_address = hankshake_splits[3].strip()
        received_master_signature = hankshake_splits[4].strip()

    
        pBit4096B58Pkcs1SHA256.debug_log(">> Letter Marque")
        pBit4096B58Pkcs1SHA256.debug_log(f"Message: {rsa_pbit_key}")
        pBit4096B58Pkcs1SHA256.debug_log(f"Address: { received_master_address}")
        pBit4096B58Pkcs1SHA256.debug_log(f"Signature: {received_master_signature}")
        
        # Let's check of the ethereum wallet signed a message compose of the public RSA key.
        ## If yes, the RSA signed the GUID and the Eth signed the pBitRSA key, so it is a valide handshake.
        ## The guy connected behind the connection has the private key of teh RSA and is owner of the Ethereum Wallet.
        bool_is_letter_marque_signed = pBit4096B58Pkcs1SHA256.is_signed_clipboard_ethereum_text_as_three_params(rsa_pbit_key, received_master_address, received_master_signature)
        pBit4096B58Pkcs1SHA256.debug_log("Is Letter Maque valide:"+str(bool_is_letter_marque_signed) )       
        return bool_is_letter_marque_signed
    
    
    def is_double_ethereum_letter_marque_handshake(guid_to_sign, clipboard_text):
        
        piece = clipboard_text.split("|")
        if len(piece) != 5:
            return False
        guid = piece[0].strip()
        ## Let's check that the guid is the same as the handshake
        if not (guid== guid_to_sign):
            return False
        address_unsecure= piece[1].strip()
        signature_of_guid = piece[2].strip()
        address_secure = piece[3].strip()
        signature_of_the_coaster_address = piece[4].strip()
        
        ## Let's check if the guid is signed by the unsecure address
        bool_is_guid_signed = pBit4096B58Pkcs1SHA256.is_signed_clipboard_ethereum_text_as_three_params(guid_to_sign, address_unsecure, signature_of_guid)
        if not bool_is_guid_signed:
            return False
        ## It is signed, so let's check if the unsecure address is signed by the secure wallet address
        bool_is_address_signed = pBit4096B58Pkcs1SHA256.is_signed_clipboard_ethereum_text_as_three_params(address_unsecure, address_secure, signature_of_the_coaster_address)
        return bool_is_address_signed
    
    def extract_etherum_address_of_clipboard(clipboard_text):
        piece = clipboard_text.split("|")
        if len(piece) == 5:
            return piece[3].strip()
        if len(piece)==3:
            return piece[1].strip()
        return ""
        

