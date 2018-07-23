#!/usr/bin/env python

from __future__ import print_function

import base64
import hashlib
from Cryptodome.Cipher import AES

encrypted = 'x8paD44M2aeUco0TT5/zIjnEBw4RCIqYtfBtZBA26D2lPdUhq38='
encrypted = base64.b64decode(encrypted)
passphrase = '123X'

nonce = encrypted[0:16]
tag = encrypted[16:32]
ciphertext = encrypted[32:]

hashedpass = hashlib.sha256(passphrase.encode('utf-8')).digest()
cipher = AES.new(hashedpass, AES.MODE_EAX, nonce)
private_key = cipher.decrypt_and_verify(ciphertext, tag)

print("Decrypted private key: ")
print(private_key.decode())
