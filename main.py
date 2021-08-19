import argparse
import hashlib
# import db_connect
import getpass

# from pbkdf2 import PBKDF2
from Crypto.Cipher import AES


def verify_master_password(entered_password):

    master_password_hash = "bd47fd8caf63798e5fbc3ae160a53be9e37ca75405fb6a1505b937d10e44efd3"

    check_hash = hashlib.sha256(str(entered_password).encode()).hexdigest()

    return check_hash == master_password_hash


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

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

    #print(args.__getattribute__("add"))
    #print(args.__getattribute__("get"))

    print("The password is correct")
    # conn = db_connect.connect()
