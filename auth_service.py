import hashlib
import os
import hmac

users = {}

def hash_password(password):
    salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 600000
    ).hex()
    return salt + ":" + hashed

def register_user(email, password):
    if "@" not in email:
        return "Invalid email", 400

    if len(password) < 12:
        return "Password too short", 400

    if email in users:
        return "Account already exists", 409

    users[email] = {
        "password": hash_password(password),
        "verified": False
    }

    return "pending_verification", 201

def verify_password(password, stored_password):
    salt, hashed = stored_password.split(":")
    calculated = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 600000
    ).hex()
    return hmac.compare_digest(calculated, hashed)
