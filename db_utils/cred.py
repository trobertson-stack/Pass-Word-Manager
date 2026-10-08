import os
from dotenv import load_dotenv
import psycopg2
import hashlib

def db_con():
    load_dotenv()
    DB_HOST = os.getenv("DB_HOST")
    DB_PORT = os.getenv("DB_PORT")
    DB_NAME = os.getenv("DB_NAME")
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    try:
        conn = psycopg2.connect(
            host=DB_HOST, 
            port=DB_PORT, 
            database=DB_NAME, 
            user=DB_USER, 
            password=DB_PASSWORD
        )
        return conn
    except Exception as e:
        st.error(f"Database connection failed: {e}")
        return None