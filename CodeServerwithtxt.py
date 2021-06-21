import socket
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import binascii
import time
##import cipher
import sqlite3
import asyncio 

 
############## SE GENERAN LLAVES CIFRADO RSA-PKCS8 Y SE ENVIA LL.PU POR SOCKET PARA RECIBIR MENSAJE Y DESCIFRAR CON LL.PR #######

#Genera llave privada y publica
private_key = RSA.generate(1024)
public_key = private_key.publickey()
print (private_key)
print (public_key)

#Socket
mysocket = socket.socket()
host = "127.0.0.1"
port = 5000
mysocket.bind((host, port))
mysocket.listen(5)
c, addr = mysocket.accept()
encrypt_str = (b"encrypted_message=")
while True:

    #Espera a recibir los datos
    data = c.recv(1024)
    data = data.replace(b"\r\n", b'') #elimina nuevas lineas


    if data == b"Client: OK":
        print("Conectado con el cliente.")
        time.sleep(2)
        c.sendall(public_key.exportKey( passphrase=None, pkcs=8)) 
        print ("Llave pública enviada al cliente...")

    elif encrypt_str in data: #Recibe mensajes cifrados y los descifra.
        data = data.replace(encrypt_str, b'')
        data = binascii.b2a_hex(data)
        #print (data.decode())
        print ("Recibido: mensaje cifrado es "+ data.decode())
        decryptor = PKCS1_OAEP.new(private_key)
        #encrypted = input(data)
        decrypted = decryptor.decrypt(bytes.fromhex(data.decode()))
        #decrypted = decryptor.decrypt(encrypted).decode()
        #decrypted = private_key.decrypt(encrypted)
        c.send(b"Server: OK")
        print ("El mensaje descifrado es:\n " + decrypted.decode())

    elif data == b"Quit": break

#Parar el servidor
c.send(b"Server stopped\n")
print ("Servidor detenido")
c.close()

###############################################################################################################

############ LUEGO DE DESCIFRAR EL MENSAJE SE GUARDA EN BASE DE DATOS SQLITE ##################################



###############################################################################################################
