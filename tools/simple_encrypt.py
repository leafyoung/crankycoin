import base64
import hashlib
from Cryptodome.Cipher import AES

passphrase = "123X"
secret = "Secret"
hashedpass = hashlib.sha256(passphrase.encode('utf-8')).digest()
cipher = AES.new(hashedpass, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(secret.encode('utf-8'))
combined = cipher.nonce + tag + ciphertext
print(base64.b64encode(combined).decode('utf-8'))

