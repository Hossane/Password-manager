#Skeleton Code for password manager

import sqlite3
from cryptography.fernet import Fernet
import getpass #for securely entering the master password
import os

#generate or load the encryption key
def load_key():
  if os.path.exists("key.key"):
    return open("key.key","rb").read()
  else:
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
      key_file.write(key)
      return key
    
key = load_key()
fernet = Fernet(key)

#creates the database table if it doesn't exist
def init_db():
  conn = sqlite3.connect("passwords.db")
  c = conn.cursor()
  c.execute('''CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, service TEXT NOT NULL, username TEXT NOT NULL, password_encrypted BLOB NOT NULL)''')
  conn.commit()
  conn.close()

def add_password(service, username, password):
  encrrypted_password = fernet.encrypt(password.encode())
  conn = sqlite3.connect("passwords.db")
  c = conn.cursor()
  c.execute("INSERT INTO passwords (service, username, password_encrypted) VALUES (?, ?, ?)", (service, username, encrrypted_password))
  conn.commit()
  conn.close()
  print(f"Password for {service} added successfully!")

def get_password(service):
  conn = sqlite3.connect("passwords.db")
  c = conn.cursor()
  c.execute("SELECT username, password_encrypted FROM passwords WHERE service = ?", (service,))
  result = c.fetchone()
  conn.close()
  if result:
    username, encrypted_password = result
    decrypted_password =  fernet.decrypt(encrypted_password).decode()
    print(f"Service: {service}\nUsername: {username}\nPassword: {decrypted_password}")
  else:
    print(f"No password found for {service}")

init_db()
master_password = "password"

print("Welcome to the Password Manager!")

input_master = getpass.getpass("Enter your master password: ")
if input_master != master_password:
  print("Incorrect master password. Exiting...")
  exit()

while True:
  print("\nWhat would you like to do?")
  print("1. Add a new password")
  print("2. Retrieve a password")
  print("3. Quit")

  choice = input("Enter your choice (1/2/3): ")

  if choice == "1":
    service = input("Enter the service/website name: ")
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    add_password(service, username, password)
  elif choice == "2":
    service = input("Enter the service/website name: ")
    get_password(service)
  elif choice == "3":
    print("Goodbye!")
    break
  else:

    print("Invalid choice. Please try again.")
