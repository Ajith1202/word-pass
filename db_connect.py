import psycopg2
from psycopg2 import Error

def connect():
    try:
        conn = psycopg2.connect(host="localhost", user="word_pass", password="word_pass", database="word_pass")
        return conn

    except (Exception, Error) as error:
        print("Error while connecting to PostgreSQL", error)