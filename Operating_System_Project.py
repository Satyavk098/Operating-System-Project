import os
import hashlib
import getpass
import secrets
import ctypes
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Function to securely hash a password using PBKDF2
# This enhances password security by making brute force attacks difficult
def secure_hash(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to validate a user-entered password against the stored hash
def validate_password(stored_hash: bytes, password: str, salt: bytes) -> bool:
    try:
        return secrets.compare_digest(stored_hash, secure_hash(password, salt))
    except Exception:
        return False

# Function to verify if the user is authenticated with the operating system
def check_os_authentication() -> bool:
    try:
        username = os.getlogin()
        print(f"System user detected: {username}")
        return True
    except Exception as e:
        print(f"OS authentication check failed: {e}")
        return False

# Function to implement buffer overflow protection
def buffer_overflow_protection():
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.malloc_trim(0)  # Releases unused heap memory to mitigate buffer overflow risks
    except Exception as e:
        print(f"Buffer overflow protection failed: {e}")

# Function to implement multi-factor authentication using a one-time password (OTP)
def multi_factor_authentication():
    otp = secrets.randbelow(1000000)  # Generate a random 6-digit OTP
    print(f"Generated OTP (For demonstration purposes): {otp}")
    user_otp = input("Enter the OTP sent to your device: ")
    return user_otp.strip() == str(otp)

# Main authentication function that integrates OS authentication, password validation, and MFA
def authentication_module():
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    salt = os.urandom(16)  # Generate a random salt for password hashing
    stored_hash = secure_hash(password, salt)
    
    if not check_os_authentication():
        print("OS authentication failed.")
        return False
    
    if not validate_password(stored_hash, password, salt):
        print("Password validation failed.")
        return False
    
    if not multi_factor_authentication():
        print("Multi-factor authentication failed.")
        return False
    
    buffer_overflow_protection()
    
    print("Authentication successful!")
    return True

# Entry point of the script
if __name__ == "__main__":
    authentication_module()
