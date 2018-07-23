#!/usr/bin/env python

from __future__ import print_function

from getpass import getpass
import sys

import base64
import hashlib
from Cryptodome.Cipher import AES

_PY3 = sys.version_info[0] > 2
if not _PY3:
    input = raw_input

passphrase = input("Choose a passphrase: ")
verifypass = input("Re-enter passphrase: ")

if passphrase != verifypass:
    print("Passphrases do not match")
    sys.exit(1)

secret = input("Secret: ")
hashedpass = hashlib.sha256(passphrase.encode('utf-8')).digest()
cipher = AES.new(hashedpass, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(secret.encode('utf-8'))

de_cipher = AES.new(hashedpass, AES.MODE_EAX, cipher.nonce)
private_key = de_cipher.decrypt_and_verify(ciphertext, tag)

print("Decrypted private key: ")
print(private_key.decode())

if not _PY3:
  combined = "{}{}{}".format(cipher.nonce, tag, ciphertext)
else:
  combined = cipher.nonce + tag + ciphertext

print("Encrypted private key: ")
if not _PY3:
    print(combined.encode('hex'))
else:
    print(base64.b64encode(combined).decode('utf-8'))
    # print(codecs.encode(combined.encode('utf-8'), 'hex').decode())

