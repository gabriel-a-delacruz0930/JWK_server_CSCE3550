import base64
import json
import time
import uuid
import jwt
from fastapi import FastAPI
from Crypto.PublicKey import RSA

app = FastAPI()

def int_to_base64url(val):
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, 'big')
    return base64.urlsafe_b64encode(val_bytes).rstrip(b'=').decode('utf-8')

def get_key_pair(expires_in_seconds):
    
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()

    kid = str(uuid.uuid4())

    expiry = int(time.time()) + expires_in_seconds
    
    return {
        "kid": kid,
        "private_key": private_key,
        "public_key": public_key,
        "expiry": expiry
    }
    
valid_key = get_key_pair(3600)
expired_key = get_key_pair(-3600)

keys_database = [valid_key, expired_key]

@app.get("/.well-known/jwks.json")
def get_jwks():
    current_time = int(time.time())
    jwks_keys = []
    for key in keys_database:
        if key["expiry"] > current_time:
            pub = key["public_key"]
            jwks_keys.append({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": key["kid"],
                "n": int_to_base64url(pub.n),
                "e": int_to_base64url(pub.e)
            })
    return {"keys": jwks_keys}

@app.post("/auth")
def authenticate(expired: bool = False):
    target_key = expired_key if expired else valid_key
    
    # Export private key to PEM format for PyJWT
    pem_private_key = target_key["private_key"].export_key('PEM')
    
    headers = {"kid": target_key["kid"]}
    payload = {
        "sub": "fake-user",
        "exp": target_key["expiry"]
    }
    
    token = jwt.encode(payload, pem_private_key, algorithm="RS256", headers=headers)
    return {"token": token}