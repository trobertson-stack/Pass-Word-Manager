import streamlit as st
import pandas as pd
import os
import psycopg2
import hashlib
from cryptography.fernet import Fernet
import secrets
from dotenv import load_dotenv
load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
KEY_FILE = "secret.key"
#DATA_FILE = "vault.json"

def load_or_create_key():
    """Loads existing key or creates a new one if it doesn't exist."""
    key = ''
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

fernet = load_or_create_key()

def hash_password(password: str) -> str:
    """Generates a secure cryptographic hash using PBKDF2 with a random salt."""
    salt = secrets.token_hex(16)  # Generate a secure 16-byte random salt
    iterations = 600000  # Current OWASP recommended iterations for SHA-256
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
    return f"{iterations}${salt}${key.hex()}"

def verify_password(password: str, stored_hash_string: str) -> bool:
    """Verifies a password against the stored string formatting."""
    try:
        # Extract the cryptographic parameters from the database string
        iterations_str, salt, stored_key_hex = stored_hash_string.split('$')
        iterations = int(iterations_str)

        # Hash the incoming password with the exact same parameters
        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        )

        # Securely compare strings to prevent timing attacks
        return secrets.compare_digest(new_key.hex(), stored_key_hex)
    except (ValueError, AttributeError):
        return False

def get_db_connection():
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

def authenticate_user(username, password):
    st.session_state.username = username
    conn = get_db_connection()
    if not conn: return False
    with conn.cursor() as cur:
        cur.execute("SELECT id, password_hash, email FROM users WHERE username = %s;", (username,))
        result = cur.fetchone()
        #st.session_state.user_id = result[0]
    conn.close()

    if result and verify_password(password, result[1]):
        st.session_state.email = result[2]
        st.session_state.user_id = result[0]
        return True
    return False

def create_user(username, password, email):
    conn = get_db_connection()
    if not conn: return False
    pwd_hash = hash_password(password)

    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (%s, %s, %s);",
                (username, pwd_hash, email)
            )
            conn.commit()
        conn.close()
        return True
    except psycopg2.errors.UniqueViolation:
        st.error("Username already exists!")
        return False

def show_auth_page():
    st.subheader("Login to your Account")
    st.title("🔒 App Authentication")
    tab1, tab2 = st.tabs(["Login", "Sign Up"])

    with tab1:
        st.subheader("Login to your Account")
        login_user = st.text_input("Username", key="login_user")
        login_pwd = st.text_input("Password", type="password", key="login_pwd")
        if st.button("Login", type="primary", use_container_width=True):
            if authenticate_user(login_user, login_pwd):
                st.session_state.logged_in = True
                st.session_state.authenticated = True
                st.session_state.username = login_user
                st.success("Successfully logged in!")
                st.rerun()
            else:
                st.error("Invalid username or password.")

    with tab2:
        st.subheader("Create a New Account")
        new_user = st.text_input("Username", key="new_user")
        new_eml = st.text_input("Email", key="new_eml")
        new_pwd = st.text_input("Password", type="password", key="new_pwd")
        confirm_pwd = st.text_input("Confirm Password", type="password", key="confirm_pwd")
        if st.button("Register", use_container_width=True):
            if new_pwd != confirm_pwd:
                st.error("Passwords do not match!")
            elif new_user and new_pwd:
                if create_user(new_user, new_pwd, new_eml):
                    st.success("Account created successfully! Head to the Login tab.")

def load_data():
    conn = get_db_connection()
    if not conn: return False
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM data WHERE user_id = %s order by id;", (st.session_state.user_id,))
        rows = cur.fetchall()
        return rows

def fetch_user_data(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT id, service, username, password FROM data WHERE user_id = %s order by id;"
    cursor.execute(query, (user_id,))
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    cursor.close()
    conn.close()
    return pd.DataFrame(rows, columns=columns)

def delete_service(pk):
    conn = get_db_connection()
    cursor = conn.cursor()
    sql_delete_query = "DELETE FROM data WHERE id = %s"
    cursor.execute(sql_delete_query, (pk,))
    conn.commit()

def update_password(record_id, new_password):
    print(new_password)
    encrypted_bytes = fernet.encrypt(new_password.encode('utf-8'))
    encrypted_string = encrypted_bytes.decode('utf-8')
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "UPDATE data SET password = %s WHERE id = %s;"
    cursor.execute(query, (encrypted_string, record_id))
    conn.commit()
    cursor.close()
    conn.close()
    st.rerun()

def main():
    st.set_page_config(page_title="Secure App Login", page_icon="🔒", layout="centered")
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "username" not in st.session_state:
        st.session_state.username = ""
    if st.session_state.logged_in:
        show_dashboard()
    else:
        show_auth_page()

def show_dashboard():
    st.title(f"🚀 Welcome, {st.session_state.username}!")
    st.write("This is your private, secured home view dashboard.")
    tab1, tab2, tab3 = st.tabs(["View accounts", "Add Account", "Edit Account"], width="stretch")
    rows = load_data()
    with tab1:
        st.subheader("🔑 Your Saved Credentials")
        if len(rows) == 0:
            st.info("Your vault is empty. Go to 'Add New Password' to get started.")
        else:
            for row in rows:
                encrypted_string = row[4]
                bytes_to_decrypt = encrypted_string.encode('utf-8')
                decrypted_bytes = fernet.decrypt(bytes_to_decrypt)
                decrypted_message = decrypted_bytes.decode('utf-8')

                with st.expander(f"🌐 {row[2]}"):
                    st.write(f"**Username:** `{row[3]}`, {decrypted_message}")

    with tab2:
        st.subheader("➕ Add a New Credential")
        with st.form("add_form", clear_on_submit=True):
            service = st.text_input("Website / Service Name (e.g., GitHub)")
            username = st.text_input("Username / Email")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Securely Save")
            if submit:
                if service and username and password:
                    original_message = password
                    encrypted_bytes = fernet.encrypt(original_message.encode('utf-8'))
                    encrypted_string = encrypted_bytes.decode('utf-8')
                    conn = get_db_connection()
                    if not conn: return False
                    user_id = st.session_state.user_id
                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                "INSERT INTO data (user_id, service, username, password) VALUES (%s, %s, %s, %s);",
                                (user_id, service, username, encrypted_string)
                            )
                            conn.commit()
                        conn.close()
                        st.rerun()
                    except psycopg2.errors.UniqueViolation:
                        st.error("Username already exists!")
                        return False
                else:
                    st.error("Please fill out all fields.")

    with tab3:
        df = fetch_user_data(4)
        if df.empty:
            st.info("No credentials found for this user.")
        else:
            h_col1, h_col2, h_col3, h_col4 = st.columns([2, 3, 3, 1.5])
            h_col1.markdown("**Service**")
            h_col2.markdown("**Username**")
            h_col3.markdown("**Password**")
            h_col4.markdown("**Action**")
            st.divider()
            for index, row in df.iterrows():
                pw = row['password']
                bytes_to_decrypt = pw.encode('utf-8')
                decrypted_bytes = fernet.decrypt(bytes_to_decrypt)
                decrypted_message = decrypted_bytes.decode('utf-8')
                col1, col2, col3, col4, col5 = st.columns([2, 3, 3, 1.5, 1.5])
                col1.text(row["service"])
                col2.text(row["username"])
                new_password = col3.text_input(
                    label=f"Password for {row['service']}",
                    value=decrypted_message,
                    type="password",
                    label_visibility="collapsed",
                    key=f"pass_{row['id']}",
                )

                if col4.button("Save", key=f"btn_{row['id']}"):
                    try:
                        update_password(row["id"], new_password)
                        st.toast(f"Successfully updated {row['service']} in database!",icon="💾",)
                    except Exception as e:
                        st.error(f"Failed to update database: {e}")
                    st.rerun()

                if col5.button("Delete", key=f"btn_d{row['id']}"):
                    try:
                        delete_service(row["id"])
                    except Exception as e:
                        st.error(f"Failed to delete record from database: {e}")
                    st.rerun()

    if st.button("Log Out"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.rerun()
    return None


if __name__ == "__main__":
    main()


