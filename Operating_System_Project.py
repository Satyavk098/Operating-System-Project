import os
import bcrypt
import pyotp
import logging
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# Setup logging
logging.basicConfig(filename='auth.log', level=logging.INFO, format='%(asctime)s - %(message)s')

app = Flask(__name__)

# Sample user database
users = {
    "user1": {
        "password_hash": generate_password_hash("SecurePass123"),
        "mfa_secret": pyotp.random_base32()
    }
}

# Function to authenticate user
def authenticate(username, password):
    if username in users and check_password_hash(users[username]['password_hash'], password):
        logging.info(f"User {username} authenticated successfully.")
        return True
    logging.warning(f"Failed authentication attempt for {username}.")
    return False

# Function to verify MFA token
def verify_mfa(username, token):
    totp = pyotp.TOTP(users[username]['mfa_secret'])
    return totp.verify(token)

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    token = data.get("token")

    if authenticate(username, password):
        if verify_mfa(username, token):
            return jsonify({"message": "Login successful!"}), 200
        return jsonify({"error": "Invalid MFA token"}), 401
    return jsonify({"error": "Invalid username or password"}), 401

# Start the Flask server
if __name__ == '__main__':
    app.run(debug=True)

