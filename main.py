import uuid
import time
from typing import List, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Query, HTTPException
from jose import jwt, jwk
import uvicorn

app = FastAPI(title="JWKS Server for CSCE 3550")

# In-memory storage for RSA keys
keys: List[Dict[str, Any]] = []

def generate_rsa_keypair(is_expired: bool = False) -> Dict[str, Any]:
    """
    Generates an RSA key pair and stores it with a unique kid and expiry.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serialize private key to PEM format for signing JWTs
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    # Serialize public key to PEM format
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Construct JWK from the public key
    rsa_key = jwk.construct(public_pem, 'RS256')
    public_jwk = rsa_key.to_dict()
    
    # Unique identifier for the key
    kid = str(uuid.uuid4())
    public_jwk.update({
        "kid": kid,
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig"
    })

    # Set expiry: expired keys in the past, valid keys in the future
    now = int(time.time())
    expires_at = now - 3600 if is_expired else now + 3600
    
    return {
        "kid": kid,
        "private_key_pem": private_pem,
        "public_jwk": public_jwk,
        "expires_at": expires_at
    }

# Initial key generation for the server
keys.append(generate_rsa_keypair(is_expired=False))
keys.append(generate_rsa_keypair(is_expired=True))

@app.get("/jwks")
@app.get("/.well-known/jwks.json")
def get_jwks():
    """
    Serves only unexpired public keys in JWKS format.
    """
    now = int(time.time())
    active_keys = [k["public_jwk"] for k in keys if k["expires_at"] > now]
    return {"keys": active_keys}

@app.post("/auth")
def auth(expired: bool = Query(False)):
    """
    Mocks authentication and returns a signed JWT.
    If 'expired=true', uses an expired key to sign the token.
    """
    now = int(time.time())
    
    # Select key based on the 'expired' query parameter
    key_data = next((k for k in keys if (k["expires_at"] <= now if expired else k["expires_at"] > now)), None)
    
    if not key_data:
        raise HTTPException(status_code=404, detail="Requested key type not found")
    
    # Set JWT expiry accordingly
    exp_time = now - 60 if expired else now + 3600
    payload = {
        "sub": "fake_user",
        "iat": now,
        "exp": exp_time
    }
    headers = {"kid": key_data["kid"]}
    
    # Sign and encode the JWT
    token = jwt.encode(payload, key_data["private_key_pem"], algorithm="RS256", headers=headers)
    
    return {"token": token}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)