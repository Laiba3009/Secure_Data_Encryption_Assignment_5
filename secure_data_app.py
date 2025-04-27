import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# File name
DATA_FILE = "users.json"

# Helpers
def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    else:
        return {}

def save_users(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data):
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(data.encode())
    return encrypted_data.decode(), key.decode()

def decrypt_data(encrypted_data, key):
    cipher_suite = Fernet(key.encode())
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()
    return decrypted_data

# Custom CSS with fixed background, fonts, and glassmorphism
def set_background():
    st.markdown("""
        <style>
        .stApp {
            background: linear-gradient(to right, #26c6da, #fbc2eb);
            color: black;
            font-family: 'Poppins', sans-serif;
        }

        .stButton>button {
            background: linear-gradient(45deg, #ff6ec4, #7873f5);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 12px;
            font-size: 16px;
            font-weight: bold;
            transition: all 0.3s ease-in-out;
        }
        .stButton>button:hover {
            transform: scale(1.05);
            background: linear-gradient(45deg, #7873f5, #ff6ec4);
                color: black;
        }

        .stTextInput>div>div>input, .stTextArea textarea {
            border-radius: 12px;
            padding: 12px;
            background: rgba(255, 255, 255, 0.7);
            color: #000000
            ;
            border: 1px solid #ccc;
            font-size: 16px;
            font-family: 'Poppins', sans-serif;
        }

        .stSidebar {
            background: rgba(255, 255, 255, 0.2);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            margin: 10px;
            padding: 20px;
        }

        .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4 {
            color: #4B0082;
        }
        </style>
    """, unsafe_allow_html=True)

# Pages
def register_page():
    st.subheader("🔐 Create New Account")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        users = load_users()
        if username in users:
            st.error("Username already exists. Try another.")
        else:
            hashed_password = hash_passkey(password)
            users[username] = {
                "passkey": hashed_password,
                "encrypted_text": None,
                "key": None
            }
            save_users(users)
            st.success("Account created successfully! Now go to Login.")

def login_page():
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pass")

    if "failed_attempts" not in st.session_state:
        st.session_state.failed_attempts = 0

    if st.button("Login"):
        users = load_users()
        if username in users:
            hashed_password = hash_passkey(password)
            if hashed_password == users[username]["passkey"]:
                st.success("Login Successful! ✅")
                st.session_state.username = username
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect password! ❌ Attempt {st.session_state.failed_attempts} of 3")
                if st.session_state.failed_attempts >= 3:
                    st.warning("Too many failed attempts. Try again later.")
                    st.session_state.username = None
        else:
            st.error("Username does not exist.")

def insert_data_page():
    st.subheader("📥 Store New Data (Encryption)")
    if st.session_state.username:
        data = st.text_area("Enter text to encrypt")
        if st.button("Encrypt & Store"):
            encrypted_data, key = encrypt_data(data)
            users = load_users()
            users[st.session_state.username]["encrypted_text"] = encrypted_data
            users[st.session_state.username]["key"] = key
            save_users(users)
            st.success("Your data is encrypted and stored securely! ✨")
    else:
        st.error("Please login first to store data.")

def retrieve_data_page():
    st.subheader("📤 Retrieve Your Data (Decryption)")
    if st.session_state.username:
        password = st.text_input("Enter your password to decrypt", type="password", key="retrieve_pass")
        if st.button("Retrieve"):
            users = load_users()
            hashed_password = hash_passkey(password)
            if hashed_password == users[st.session_state.username]["passkey"]:
                encrypted_text = users[st.session_state.username]["encrypted_text"]
                key = users[st.session_state.username]["key"]
                if encrypted_text and key:
                    decrypted_text = decrypt_data(encrypted_text, key)
                    st.success("Here is your decrypted text:")
                    st.info(decrypted_text)
                else:
                    st.warning("No data stored yet.")
            else:
                st.error("Incorrect password! ❌")
    else:
        st.error("Please login first to retrieve data.")

def home_page():
    st.subheader("🏠 Welcome to Secure Data Encryption System!")
    st.write("Secure your important data with encryption and password protection.🔐✨")

# Main App
def main():
    st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒", layout="wide")

    if "username" not in st.session_state:
        st.session_state.username = None

    set_background()

    st.sidebar.title("🔒 Navigation")
    menu = ["Home", "Register", "Login", "Insert Data", "Retrieve Data"]
    choice = st.sidebar.radio("Go to", menu)

    if choice == "Home":
        home_page()
    elif choice == "Register":
        register_page()
    elif choice == "Login":
        login_page()
    elif choice == "Insert Data":
        insert_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()

if __name__ == "__main__":
    main()
