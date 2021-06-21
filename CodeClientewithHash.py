import socket
import os
import sys
import subprocess
import binascii
import time
import asyncio
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

arr = []

print('Los archivos pertenecen a los siguientes hashes:\n')
for i in [0,1,2]:
    b=i+1
    b = str(b)
    n= ('./Archivos/archivo_'+b+'.txt')
    with open(n) as f:
        hola = f.read().splitlines()
        hash1 = hola[0]

        comilla = "'"
        hash2 = comilla + hash1 + comilla
        command = "python hash-id.py " 
        command2 = hash1 
        command3 = " | grep -A1 Possible | grep -v Hash | awk '{print $2}'"
        command4 = command + command2 + command3
        hashcat = subprocess.Popen(command4,shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        a = hashcat.communicate()[0].decode()
        if i == 0:
            os.system('hashcat -a 0 -m 0 ./Archivos/archivo_'+b+'.txt ./Archivos/diccionario_1.dict ./Archivos/diccionario_2.dict -o dictFull')
            os.system("cat dictFull | " + "sed 's/:/ /g' | " + "awk '{print$2}'" + " > passFile")
        else: 
            print ("ERROR")
    
        print('archivo '+b+ ' = '+a.rstrip('\n'))

with open('./Archivos/archivo_4.txt') as f:
        hola = f.read().splitlines()
        hash1 = hola[0]

        comilla = "'"
        hash2 = comilla + hash1 + comilla
        command = "python hash-id.py " 
        command2 = hash1 
        command3 = " | grep -A2 Least| awk 'NR==3' | grep -v Hash | awk '{print $2}'"
        command4 = command + command2 + command3
        hashcat = subprocess.Popen(command4,shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        a = hashcat.communicate()[0].decode()
        if i == 0:
            os.system('hashcat -a 0 -m 1000 ./Archivos/archivo_4.txt ./Archivos/diccionario_1.dict ./Archivos/diccionario_2.dict -o dictFull')
            os.system("cat dictFull | " + "sed 's/:/ /g' | " + "awk '{print$2}'" + " > passFile")
        else: 
            print ("ERROR")
        print('archivo 4 = '+ a.rstrip('\n'))

with open('./Archivos/archivo_5.txt') as f:
        hola = f.read().splitlines()
        hash1 = hola[1]
        comilla = "'"
        hash2 = comilla + hash1 + comilla
        command = "python hash-id.py " 
        command2 = hash2 
        command3 = " | grep -v Analyzing | awk '{print $2 $3}' "
        command4 = command + command2 + command3

        hashcat = subprocess.Popen(command4,shell=True, stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        a = hashcat.communicate()[0].decode()
        if i == 0:
            os.system('hashcat -a 0 -m 1800 ./Archivos/archivo_5.txt ./Archivos/diccionario_1.dict ./Archivos/diccionario_2.dict -o dictFull')
            os.system("cat dictFull | " + "sed 's/:/ /g' | " + "awk '{print$2}'" + " > passFile")
        else: 
            print ("ERROR")
        print('archivo 5 = '+a.rstrip('\n'))



O = open ('NewHash.txt', 'w')
with open('passFile', 'r') as g:
    hola = g.read().splitlines()
    j = 0 
    while True:
        if j < len(hola):
            hola1 = hola[j]
            x =  PBKDF2( hola1,b'hola', 16, 1000, None, None)
            y = binascii.b2a_hex(x)
       
            print (y.decode())
            O.write(y.decode()+'\n')
            j = j+1
        else:
            break
O.close()
g.close()


#########################################################################################################################


######## MEDIANTE SOCKET SE RECIBE LLAVE PÚBLICA, SE CIFRA EL MENSAJE Y SE ENVÍA AL "SERVIDOR" ##########################

server = socket.socket()
host = "127.0.0.1"
port = 5000
x = "NewHash.txt" 
server.connect((host, port))

server.sendall(b"Client: OK")

server_string = server.recv(1024)

server_string = server_string.replace(b"Llave publica=", b'')
server_string = server_string.replace(b"\r\n", b'')

server_public_key = RSA.importKey(server_string)


with open (x, 'rb') as m:
    encryptor = PKCS1_OAEP.new(server_public_key)
    message = m.read().splitlines() #archivo a enviar
    l = 0
    while True:
        if l < len(message):
            time.sleep(0.2)
            hi = message[l]
            encrypted = encryptor.encrypt(hi)
            y = binascii.b2a_hex(encrypted)
            notificacion = b"encrypted_message="
            time.sleep(0.25)
            server.sendall( notificacion + encrypted)
            l=l+1
            arr.append(encrypted)
            print("Mensaje cifrado enviado...")
        else:
            m.close()
            break

O = open ('txt.txt', 'w')
for i in arr:
    O.write(i)
O.close

server_response = server.recv(2048)
server_response = server_response.replace(b"\r\n", b'')
if server_response == b"Server: OK":
    print ("Servidor descifra mensaje correctamente!")


server.sendall(b"Quit")

print("Sesion finalizada")
server.close()


