import streamlit as st
from streamlit import session_state as ss
import time
import bcrypt

def freeze_check():
    if (time.time() - ss.last_unsuccessful_attempt) < 60:
        if not ss.freeze_login and ss.unsuccessful_attempts > 30:
                ss.freeze_login = True
        else:
            ss.unsuccessful_attempts += 1
    else:
        ss.freeze_login = False
        ss.unsuccessful_attempts = 0

def hash_password(password:str):
    password_bytes = password.encode()
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed

@st.dialog('Log in')
def login():
    username = st.text_input(label='User Name')
    password = st.text_input(label='Password', type='password')

    if st.button('Submit'):
        if username in st.secrets['users'] and bcrypt.checkpw(password.encode(), st.secrets['users'][username].encode()):
            ss.username = username
            ss.login = True
            st.rerun()
        else:
            st.write(password)
            # st.write(hash_password(password))
            freeze_check()
            if ss.freeze_login:
                st.warning(f'Try again in {60 - (time.time() - ss.last_unsuccessful_attempt):.2f} seconds!')
            else:
                st.error('Invalid Credentials!')
                ss.last_unsuccessful_attempt = time.time()
                ss.unsuccessful_attempts += 1

@st.dialog('Register')
def register():
    username = st.text_input(label='User Name')
    password = st.text_input(label='Password', type='password')

    if st.button('Submit'):
        if username in st.secrets['users'] and st.secrets['users'][username] == hash_password(password):
            ss.username = username
            ss.login = True
            st.rerun()
        else:
            freeze_check()
            if ss.freeze_login:
                st.warning(f'Try again in {60 - (time.time() - ss.last_unsuccessful_attempt):.2f} seconds!')
            else:
                st.error('Invalid Credentials!')
                ss.last_unsuccessful_attempt = time.time()
                ss.unsuccessful_attempts += 1

def logout():
    ss.login = False

if 'freeze_login' not in ss:
    ss.freeze_login = False
if 'unsuccessful_attempts' not in ss:
    ss.unsuccessful_attempts = 0
if 'last_unsuccessful_attempt' not in ss:
    ss.last_unsuccessful_attempt = time.time()


# st.write('Testing')
# st.write(st.secrets)

# st.write(st.session_state.logins)

c1, c2, c3 = st.columns([4, 1, 1])

if 'login' not in ss or not ss.login:
    c3.button(label='Log in', type='primary', on_click=login)
    c2.button(label='Register', type='secondary', on_click=register)
else:
    c3.button(label='Log out', type='primary', on_click=logout)
    c2.write(f'Hello, {ss.username}!')