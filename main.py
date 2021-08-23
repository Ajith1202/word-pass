import argparse
import hashlib
import sys
import binascii
# import db_connect
import getpass
import os
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
#from backports.pbkdf2 import pbkdf2_hmac

from queries import *


def verify_master_password(entered_password):

    master_password_hash = "bd47fd8caf63798e5fbc3ae160a53be9e37ca75405fb6a1505b937d10e44efd3"

    check_hash = hashlib.sha256(str(entered_password).encode()).hexdigest()

    return check_hash == master_password_hash

def decrypt_password(master_hash, ciphertext, master_salt):

    key = PBKDF2(master_hash, master_salt).read(16)

    ciphertext = binascii.unhexlify(ciphertext.encode())    # converting back to bytes-object data

    tag = ciphertext[-16:]
    nonce = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext[16:-16], tag)
        return plaintext
    except ValueError as error:
        print("Decryption failed: ", error)


def encrypt_password(master_hash, password, master_salt):

    key = PBKDF2(master_hash, master_salt).read(16)
    
    cipher = AES.new(key, AES.MODE_EAX)

    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(password.encode())

    return (nonce, ciphertext, tag)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    master_password_hash = "bd47fd8caf63798e5fbc3ae160a53be9e37ca75405fb6a1505b937d10e44efd3"
    #add, retrievepassword, updateusername, updatepassword, deleterecord, deleteall
    parser.add_argument("-a", "--add", type=str, nargs=3, help="Add a new password")
    parser.add_argument("-g", "--get", type=str, nargs=1, help="Get password for a domain")

    parser.add_argument("-un", "--updatename", type=str, nargs=2, help="Update username for a domain")
    parser.add_argument("-up", "--updatepassword", type=str, nargs=2, help="Update password for a domain")
    parser.add_argument("-dr", "--deleterecord", type=str, nargs=1, help="Delete details of a domain")
    parser.add_argument("-da", "--deleteall", type=str, nargs=1, help="Delete details of all domains")


    args = parser.parse_args()

    try:
        master_password = getpass.getpass("Enter your master password: ")
    except Exception as error:
        print('ERROR', error)
        exit()
    
    if not verify_master_password(master_password):
        print("The password you entered is incorrect")
        exit()


    salt = b'\xd18\xbf~No\xcb\xf5L\xcc\xfd\xda\xf9K?d'   # using os.urandom(16)

    if args.__getattribute__("add"):
        arguments = args.__getattribute__("add")

        domain_name = arguments[0]
        username = arguments[1]
        nonce, ciphertext, tag = encrypt_password(master_password_hash, arguments[2], salt)

        password_to_be_stored = nonce[:] + ciphertext + tag[:]

        password_to_be_stored = binascii.hexlify(password_to_be_stored).decode()    # string representation of hexadecimal representation of bytes-object data    

        add_password(domain_name, username, password_to_be_stored)

        #print(decrypt_password(master_password_hash, nonce[:] + ciphertext + tag[:], salt))
    
    elif args.__getattribute__("get"):
        arguments = args.__getattribute__("get")

        domain_name = arguments[0]
        ciphertext = retrieve_password(domain_name)[0]

        print(decrypt_password(master_password_hash, ciphertext, salt).decode())

    elif args.__getattribute__("updatename"):
        arguments = args.__getattribute__("updatename")

        domain_name = arguments[0]
        updated_name = arguments[1]

        update_username(domain_name, updated_name)

    elif args.__getattribute__("updatepassword"):
        arguments = args.__getattribute__("updatepassword")

        domain_name = arguments[0]
        updated_password = arguments[1]

        update_password(domain_name, updated_password, encrypt_password, master_password_hash, salt)