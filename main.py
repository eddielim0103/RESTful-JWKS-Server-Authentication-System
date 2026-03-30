import time
import sqlite3
from typing import List, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Query, HTTPException
from jose import jwt, jwk
import uvicorn

app = FastAPI(title="JWKS Server for CSCE 3550")

def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def generate_and_save_key(is_expired: bool = False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    now = int(time.time())
    expires_at = now - 3600 if is_expired else now + 3600
    
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (private_pem, expires_at))
    conn.commit()
    conn.close()

init_db()
generate_and_save_key(is_expired=False)
generate_and_save_key(is_expired=True)

@app.get("/jwks")
@app.get("/.well-known/jwks.json")
def get_jwks():
    now = int(time.time())
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (now,))
    rows = cursor.fetchall()
    conn.close()
    
    active_keys = []
    for kid, private_pem in rows:
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        rsa_key = jwk.construct(public_pem, 'RS256')
        public_jwk = rsa_key.to_dict()
        
        public_jwk.update({
            "kid": str(kid), 
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig"
        })
        active_keys.append(public_jwk)
        
    return {"keys": active_keys}

@app.post("/auth")
def auth(expired: bool = Query(False)):
    now = int(time.time())
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    if expired:
        cursor.execute('SELECT kid, key FROM keys WHERE exp <= ?', (now,))
    else:
        cursor.execute('SELECT kid, key FROM keys WHERE exp > ?', (now,))
        
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=404, detail="Requested key type not found")
        
    kid, private_pem = row
    
    exp_time = now - 60 if expired else now + 3600
    payload = {
        "sub": "fake_user",
        "iat": now,
        "exp": exp_time
    }
    headers = {"kid": str(kid)}
    
    token = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)
    
    return {"token": token}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)