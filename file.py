import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import getpass

#Function to generate key
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
    print("Key generated and saved to key.key")

# Function to load the key
def load_key():
    return open("key.key", "rb").read()

# Function to encrypt a file using key
def encrypt_file_with_key(file_path, key_path):
    key = open(key_path, "rb").read()
    fernet = Fernet(key)
    
    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)
    
    with open(file_path + ".enc", "wb") as file:
        file.write(encrypted_data)
    
    print(f"File {file_path} encrypted to {file_path}.enc using key file.")

# Function to decrypt a file using key
def decrypt_file_with_key(file_path, key_path):
    key = open(key_path,"rb").read()
    fernet = Fernet(key)
    
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)
    
    with open(file_path.rstrip(".enc"), "wb") as file:
        file.write(decrypted_data)
    
    print(f"File {file_path} decrypted to {file_path.rstrip('.enc')} using key file.")

# Function to derive key from password
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm= hashes.SHA256(),
        length= 32,
        salt= salt,
        iterations= 100000,
        backend= default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to encrypt file with password
def encrypt_with_password(file_path, password):
    salt = os.urandom(16)  # Random salt for each encryption
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    
    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    with open(file_path + ".enc", "wb") as file:
        file.write(salt + encrypted_data)  # Save salt + encrypted data
    
    print(f"File {file_path} encrypted to {file_path}.enc using password.")

# Function to decrypt the file using a password
def decrypt_with_password(file_path, password):
    with open(file_path, "rb") as file:
        data = file.read()
        salt = data[:16]  # Extract the salt
        encrypted_data = data[16:]  # The actual encrypted data

    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(file_path.rstrip(".enc"), "wb") as file:
        file.write(decrypted_data)

    print(f"File {file_path} decrypted to {file_path.rstrip('.enc')} using password.")

def length_check(password, min_length = 10):
    return len(password) >= min_length

def check_password(password):
    upper = any(c.isupper() for c in password)
    lower = any(c.islower() for c in password)
    digit = any(c.isdigit() for c in password)
    special = any(c in " ! @ # $ % ^ & * ( ) - _ = + \ | [ ] { } ; : / ? . >" for c in password)

    return sum([upper, lower, digit, special])

def check(password):
    score = 0

    if length_check(password):
        score += 2
    else:
        print("Use at lease 10 characters")

    diversity = check_password(password)
    score += diversity
    if diversity <3:
        print("Include upper case, lowercase, digits and special characters")

    if score <3:
        strength = "Weak"
    elif score <5:
        strength = "Mid"
    else:
        strength = "Strong"

    return{"Score": score, "Strength": strength}
# Main function to choose actions
def main():
    while True:
        print("File Encryption and Decryption Tool")
        print("Choose the encryption method: ")
        print("1. Key_Based")
        print("2. Password_Based")
        print("3. Quit")
        
        method_choice = input("\nEnter your choice(1/2/3): ")

        if method_choice == "1":
            while True:
                print("\nYou have choosen Key_Based encryption/decryption.")
                print("1. Generate Key")
                print("2. Encrypt file")
                print("3. Decrypt file")
                print("4. Back to main menu")

                choice = input("Enter your choice: ")

                if choice == '1':
                        # generate_key()
                        key = Fernet.generate_key()
                        with open("key.key", "wb") as key_file:
                            key_file.write(key)
                        print("Key generated and saved to key.key")

                elif choice == '2':
                        file_path = input("Enter the path to the file to encrypt: ")
                        key_path = input("Enter the path to key file: ")
                        encrypt_file_with_key(file_path, key_path)
                    
                elif choice == "3":
                        file_path = input("Enter the path to the file to decrypt: ")
                        key_path = input("Enter the path to key file: ")
                        decrypt_file_with_key(file_path, key_path)
                    
                elif choice == "4":
                        break

                else:
                        print("Invalid choice.")

        elif method_choice == "2":
            while True:
                print("\nYou have choosen Password_Based encryption/decryption.")
                print("1. Encrypt file")
                print("2. Decrypt file")
                print("3. Back to main menu")

                choice = input("Enter your choice: ")

                if choice == '1':
                    file_path = input("Enter the path to the file to encrypt: ")
                    while True:
                        password = getpass.getpass("Enter the password: ")
                        strength_check = check(password)
                        print(f"Password Strength: {strength_check['Strength']}")

                        if strength_check['Strength'] == "Weak":
                            print("Please use a stronger password.")
                        else:
                            break
                    encrypt_with_password(file_path, password)
                
                elif choice == "2":
                    file_path = input("Enter the path to the file to decrypt: ")
                    password= getpass.getpass("Enter the password: ")
                    decrypt_with_password(file_path, password)
                
                elif choice == "3":
                    break

                else:
                    print("Invalid choice.")

        elif method_choice == "3":
            print("Thank you.")
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()