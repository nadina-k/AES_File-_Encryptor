import os
import sys
import hashlib
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16
KEY_SIZE = 32
SALT_SIZE = 16

# Fun ASCII banner
def print_banner():
    print(r"""
   ___  ______ _____      _                 _             _             
  / _ \ |  ____|  __ \    | |               | |           | |            
 | | | || |__  | |__) |__ | |_   _ _ __ ___ | | ___   __ _| |_ ___  _ __ 
 | | | ||  __| |  ___/ _ \| | | | | '_ ` _ \| |/ _ \ / _` | __/ _ \| '__|
 | |_| || |____| |  | (_) | | |_| | | | | | | | (_) | (_| | || (_) | |   
  \___/ |______|_|   \___/|_|\__,_|_| |_| |_|_|\___/ \__,_|\__\___/|_|   
""")
    print("Welcome to the Interactive AES File Encryptor!\n")

def pad(data):
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=100000)

def encrypt_file(file_path, password):
    try:
        salt = get_random_bytes(SALT_SIZE)
        key = derive_key(password.encode(), salt)
        iv = get_random_bytes(BLOCK_SIZE)

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext))

        with open(file_path + ".enc", 'wb') as f:
            f.write(salt + iv + ciphertext)

        print(f"[+] Encrypted: {file_path}.enc\n")
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}\n")
    except Exception as e:
        print(f"[!] Error: {e}\n")

def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
        ciphertext = data[SALT_SIZE + BLOCK_SIZE:]

        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext))

        output_path = file_path.replace(".enc", ".dec")
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"[+] Decrypted: {output_path}\n")
    except FileNotFoundError:
        print(f"[!] File not found: {file_path}\n")
    except ValueError:
        print("[!] Incorrect password or corrupted file.\n")
    except Exception as e:
        print(f"[!] Error: {e}\n")

def main():
    print_banner()
    while True:
        print("Please choose an option:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ").strip()
        if choice == '1':
            file_path = input("Enter the path to the file to encrypt: ").strip()
            password = input("Enter the password: ").strip()
            encrypt_file(file_path, password)
        elif choice == '2':
            file_path = input("Enter the path to the file to decrypt (.enc): ").strip()
            password = input("Enter the password: ").strip()
            decrypt_file(file_path, password)
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.\n")

if __name__ == "__main__":
    main()