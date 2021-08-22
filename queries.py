from db_connect import connect
import psycopg2
from psycopg2 import Error

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