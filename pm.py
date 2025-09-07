import sqlite3
from cryptography.fernet import Fernet
import getpass 
import os
import bcrypt
import base64
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Define paths for database and config files
def get_app_data_path():
  # Determine base path
  if getattr(sys, 'frozen', False):
    base_path = os.path.dirname(sys.executable)
  else:
    base_path = os.path.dirname(os.path.abspath(__file__))
    
  # Create data directory if it doesn't exist
  data_path = os.path.join(base_path, 'data')
  os.makedirs(data_path, exist_ok=True)
  return data_path

# Define file paths
APP_DATA_PATH = get_app_data_path()
DB_PATH = os.path.join(APP_DATA_PATH, 'passwords.db')
CONFIG_FILE = os.path.join(APP_DATA_PATH, 'config.txt')
SALT_FILE = os.path.join(APP_DATA_PATH, 'salt.key')

# Master password management
def setup_master_password(master_pwd):
  hashed = bcrypt.hashpw(master_pwd.encode(), bcrypt.gensalt())
  with open(CONFIG_FILE, "wb") as f:
    f.write(hashed)
  print("Master password set successfully!")
  return True

# Verify the master password
def verify_master_password(attempted_pwd):
  with open(CONFIG_FILE, "rb") as f:
    hashed = f.read()
  
  # Check the password
  if bcrypt.checkpw(attempted_pwd.encode(), hashed):
    return attempted_pwd
  else:
    print("Incorrect master password!")
    return None

# Derive a Fernet key from the master password
def get_fernet_key(password):
  password = password.encode() 
  if os.path.exists(SALT_FILE):
    with open(SALT_FILE, "rb") as f:
      salt = f.read()
  else:
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
      f.write(salt)  
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
  )
  key = base64.urlsafe_b64encode(kdf.derive(password))
  return key

# Initialize the database
def init_db():
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute('''CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, service TEXT NOT NULL, username TEXT NOT NULL, password_encrypted BLOB NOT NULL)''')
  conn.commit()
  conn.close()

# Add a new password entry
def add_password(service, username, password, fernet):
  encrypted_password = fernet.encrypt(password.encode())
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute("INSERT INTO passwords (service, username, password_encrypted) VALUES (?, ?, ?)", (service, username, encrypted_password))
  conn.commit()
  conn.close()
  print(f"Password for {service} added successfully!")

# Check if the input is in the db
def check_input(service):
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute("SELECT service FROM passwords WHERE service = ?", (service))
  result = c.fetchone()
  conn.close()

  if result != None:
    return True
  else: 
    print("\nEntry not found")
    input("Press Enter to continue...")
    return False

# Retrieve a password entry
def get_password(service):
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute("SELECT username, password_encrypted FROM passwords WHERE service = ?", (service))
  result = c.fetchone()
  conn.close()
  if result:
    username, encrypted_password = result
    decrypted_password =  fernet.decrypt(encrypted_password).decode()
    print(f"Service: {service}\nUsername: {username}\nPassword: {decrypted_password}")
    input("Press Enter to continue...")
  else:
    print(f"No password found for {service}")

# List all services
def list_service():
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute("SELECT service FROM passwords")
  results = c.fetchall()
  conn.close()
  print("Services:")
  if results == []:
    print("No entries found.")
    return False
  else:
    for service in results:
      print(f"{str(service)[2:-3]}")
    return True

# Delete a password entry
def delete_password(service):
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute("SELECT service FROM passwords where service = ?", (service))
  c.execute("DELETE FROM passwords where service = ?", (service))
  conn.commit()
  conn.close()
  print(f"The entry {service} has been deleted")

# Edit a password entry
def edit_password(service, new_password):
  encrypted_password = fernet.encrypt(new_password.encode())
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute("UPDATE passwords SET password_encrypted = ? where service = ?",(encrypted_password,service))
  conn.commit()
  conn.close()
  print("Updating database...")
  print(f"password for {service} successfully changed.")

# Delete all password entries
def delete_all_passwords():
  conn = sqlite3.connect(DB_PATH)
  c = conn.cursor()
  c.execute("DELETE FROM passwords")
  conn.commit()
  conn.close()
  print("All entries have been deleted.")

# Main program loop
if __name__ == "__main__":
  print("Welcome to the Password Manager!")

  if not os.path.exists(CONFIG_FILE):
    master_pwd = getpass.getpass("Set your master password: ")

    setup_master_password(master_pwd)

  attempted_pwd = getpass.getpass("Enter your master password: ")

  correct_password = verify_master_password(attempted_pwd)
  key = get_fernet_key(correct_password)
  fernet = Fernet(key)
  
  while True:
    if not os.path.exists(DB_PATH):
      init_db()


    print("\nWhat would you like to do?")
    print("1. Add a new password")
    print("2. Retrieve a password")
    print("3. List all services")
    print("4. Delete a password")
    print("5. Edit a password")
    print("q. Quit")

    choice = input("Enter your choice: ")

    if choice == "1":
      service = input("Enter the service/website name: ")
      username = input("Enter your username: ")
      password = getpass.getpass("Enter your password: ")
      if service != "" and username != "" and password != "":
        add_password(service, username, password, fernet)
      else:
        print("All fields are required!")
      input("Press Enter to continue...")
    elif choice == "2":
      if list_service():
        service = input("Enter the service/website name: ")
        if check_input(service):
          get_password(service) 
      else:
        input("Press Enter to continue...")

    elif choice == "3":
      list_service()
      input("Press Enter to continue...")

    elif choice == "4":
      if list_service():
        print("Type \"delete all\" to delete all entries.")
        service = input("Enter a service/website you want to delete: ")
        if service == "delete all":
          delete_all_passwords()
          input("Press Enter to continue...")
          continue
        if check_input(service):
          delete_password(service)
      else:
        input("Press Enter to continue...")
    elif choice == "5":
      if list_service():
        service = input("Enter the service/website you want to edit: ")
        if check_input(service):
          updated_password = input("Enter the new password: ")
          edit_password(service,updated_password)
      else:
        input("Press Enter to continue...")
    elif choice == "q":
      print("Goodbye!")
      break
    else:
      print("Invalid choice. Please try again.")
      input("Press Enter to continue...")