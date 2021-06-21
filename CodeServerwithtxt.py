import socket
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import binascii
import time
import sqlite3
import asyncio 

 
private_key = RSA.generate(1024)
public_key = private_key.publickey()
print (private_key)
print (public_key)

mysocket = socket.socket()
host = "127.0.0.1"
port = 5000
mysocket.bind((host, port))
mysocket.listen(5)
c, addr = mysocket.accept()
encrypt_str = (b"encrypted_message=")
while True:

   
    data = c.recv(1024)
    data = data.replace(b"\r\n", b'') #elimina nuevas lineas


    if data == b"Client: OK":
        print("Conectado con el cliente.")
        time.sleep(2)
        c.sendall(public_key.exportKey( passphrase=None, pkcs=8)) 
        print ("Llave pública enviada al cliente...")

    elif encrypt_str in data: 
        data = data.replace(encrypt_str, b'')
        data = binascii.b2a_hex(data)
        print ("Recibido: mensaje cifrado es "+ data.decode())
        decryptor = PKCS1_OAEP.new(private_key)
        decrypted = decryptor.decrypt(bytes.fromhex(data.decode()))
        c.send(b"Server: OK")
        print ("El mensaje descifrado es:\n " + decrypted.decode())

    elif data == b"Quit": break


c.send(b"Server stopped\n")
print ("Servidor detenido")
c.close()



