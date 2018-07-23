#!/usr/bin/env python

from __future__ import print_function

import sys
from getpass import getpass

import base64
import hashlib
from Cryptodome.Cipher import AES

# Python 2 & 3 compatibility
_PY3 = sys.version_info[0] > 2
if not _PY3:
  input = raw_input

encrypted = input("Cipher: ")
encrypted = base64.b64decode(encrypted)
passphrase = input("Enter passphrase: ")

nonce = encrypted[0:16]
tag = encrypted[16:32]
ciphertext = encrypted[32:]

hashedpass = hashlib.sha256(passphrase.encode('utf-8')).digest()
cipher = AES.new(hashedpass, AES.MODE_EAX, nonce)
private_key = cipher.decrypt_and_verify(ciphertext, tag)

print("Decrypted private key: ")
print(private_key.decode())
