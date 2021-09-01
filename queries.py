from db_connect import connect
import psycopg2
from psycopg2 import Error

import binascii

def add_password(domain_name, username, password):

    try:
        conn = connect()
        cursor = conn.cursor()
        
        #cursor.execute("grant ALL privileges on passwords to word_pass;")
        sql_query = """insert into passwords (domain_name, username, password) values (%s, %s, %s);"""
        values = (domain_name, username, password)
        cursor.execute(sql_query, values)
        conn.commit()
        cursor.close()
        conn.close()

    except (Exception, Error) as error:
        print(error)
        
def retrieve_password(domain_name):

    try:
        conn = connect()
        cursor = conn.cursor()
        
        #cursor.execute("grant ALL privileges on passwords to word_pass;")
        sql_query = """select password from passwords where domain_name=%s;"""
        values = (domain_name,)
        cursor.execute(sql_query, values)
        res = cursor.fetchone()
        conn.commit()
        cursor.close()
        conn.close()
        return res

    except (Exception, Error) as error:
        print(error)


def update_username(domain_name, username):

    try:
        conn = connect()
        cursor = conn.cursor()
        
        #cursor.execute("grant ALL privileges on passwords to word_pass;")
        sql_query = """update passwords set username=%s where domain_name=%s;"""
        values = (username, domain_name)
        cursor.execute(sql_query, values)
        conn.commit()
        cursor.close()
        conn.close()

    except (Exception, Error) as error:
        print(error)

def update_password(domain_name, password, encrypt_password, master_password_hash, master_salt):

    try:
        conn = connect()
        cursor = conn.cursor()
        
        #cursor.execute("grant ALL privileges on passwords to word_pass;")
        sql_query = """update passwords set password=%s where domain_name=%s;"""

        nonce, ciphertext, tag = encrypt_password(master_password_hash, password, master_salt)

        password_to_be_stored = nonce[:] + ciphertext + tag[:]

        password_to_be_stored = binascii.hexlify(password_to_be_stored).decode()    # string representation of hexadecimal representation of bytes-object data    


        values = (password_to_be_stored, domain_name)
        cursor.execute(sql_query, values)
        conn.commit()
        cursor.close()
        conn.close()

    except (Exception, Error) as error:
        print(error)

def delete_password(domain_name):

    try:
        conn = connect()
        cursor = conn.cursor()
        
        #cursor.execute("grant ALL privileges on passwords to word_pass;")
        sql_query = """delete from passwords where domain_name=%s;"""
        values = (domain_name,)
        cursor.execute(sql_query, values)
        conn.commit()
        cursor.close()
        conn.close()

    except (Exception, Error) as error:
        print(error)
