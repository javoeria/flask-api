from flask import Flask
from flask_restful import Resource, Api

import os
import string
import random
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms, modes

app = Flask(__name__)
api = Api(app)

backend = default_backend()
salt = b"##h\x12\x9e\xc4N\xea!VO\xbd\xdc\xb8\xec\xa5"
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
key = kdf.derive(b"my great password")

iv = b"\x98\x1b\xba3\xf4k.\xb1'\xec\xb0\x7f\x14\xa1\xec\xbc"
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

diccionario_key = dict()
try:
  f = open("claves.txt", "rb")
  f_id = open("id.txt", "r")
  linea = f.read(32)
  linea_id = f_id.read(16)

  while len(linea)!=0 and len(linea_id)!=0:
    diccionario_key[linea_id] = linea
    linea = f.read(32)
    linea_id= f_id.read(16)

  f.close()
  f_id.close()
except:
  print("Error")

def unique_strings(k: int, pool: str=string.ascii_letters+string.digits) -> set:
    """Generate a set of unique string tokens.

    k: Length of each token
    pool: Iterable of characters to choose from

    For a highly optimized version:
    https://stackoverflow.com/a/48421303/7954504
    """
    join = ''.join
    return join(random.choices(pool, k=k))

class Info(Resource):
    def get(self):
        return {'Create Key': '/create', 'Get Key': '/get/<key-id>', 'Show All Keys': '/all'}

class Create_Key(Resource):
    def get(self):
        f = open("claves.txt", "ab")
        f_id = open("id.txt", "a")
        # newKey = unique_strings(k=32)
        newKey = secrets.token_hex(32)
        keyId = unique_strings(k=16)

        encryptor = cipher.encryptor()
        ct = encryptor.update(str.encode(newKey))
        encryptor.finalize()

        f.write(ct)
        f_id.write(keyId)

        f.close()
        f_id.close()  
        diccionario_key[keyId] = ct
        return {'key': newKey, 'key-id': keyId}

class Get_Key(Resource):
    def get(self, keyId):
        if (diccionario_key.get(keyId) != None):
            decryptor = cipher.decryptor() 
            key = decryptor.update(diccionario_key.get(keyId))
            decryptor.finalize()
            return {'key': key.decode(), 'key-id': keyId}
        else:
            return {'key': 'null', 'key-id': 'null'}

class Get_All(Resource):
    def get(self):
        array = []
        for keyId in diccionario_key:
            decryptor = cipher.decryptor() 
            key = decryptor.update(diccionario_key.get(keyId))
            decryptor.finalize()
            array.append({'key': key.decode(), 'key-id': keyId})

        return array

class Delete_All(Resource):
    def get(self):
        open('claves.txt', 'w').close()
        open('id.txt', 'w').close()
        diccionario_key.clear()
        return {'close': True}

api.add_resource(Info, '/')
api.add_resource(Create_Key, '/create')
api.add_resource(Get_Key, '/get/<keyId>')
api.add_resource(Get_All, '/all')
api.add_resource(Delete_All, '/delete')

if __name__=='__main__':
    
    app.run(debug=True)
