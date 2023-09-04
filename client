from socket import *
from Crypto.Cipher import ARC4
import random
import string
import rsa
import hashlib
import base64
import sys

HOST = '127.0.0.1'
PORT = 5555
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_DGRAM)
#1
name_c = input("please enter your name: ")
NB = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
client_socket.sendto(name_c.encode('utf-8'), ADDR)
client_socket.sendto(NB.encode('utf-8'), ADDR)
#2
reply, addr = client_socket.recvfrom(1024)
name_s = reply.decode('utf-8')
reply, addr = client_socket.recvfrom(1024)
NA = reply.decode('utf-8')
reply, addr = client_socket.recvfrom(1024)
pubkey_s = reply.decode('utf-8')
with open('public.pem') as publickfile:  #check public key from Alice
    pubkey_c = rsa.PublicKey.load_pkcs1(publickfile.read())
if str(pubkey_c) == pubkey_s:
    print("pk matched...")
elif str(pubkey_c) != pubkey_s:
    print("pk wrong! program terminated!")
    client_socket.close()
    sys.exit()
#3
pw = input("please input the password: ")
C1 = rsa.encrypt(pw.encode('utf-8'), pubkey_c)  #RSA encode
K = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
C2 = rsa.encrypt(K.encode('utf-8'), pubkey_c)  #RSA encode
client_socket.sendto(C1, ADDR)
client_socket.sendto(C2, ADDR)
#4
reply, addr = client_socket.recvfrom(1024) 
status = reply.decode('utf-8')
if status == 'Connection Okay':
    print('Connection Okay!')
else:
    print('Connection failed, please quit!')
    client_socket.close()
    sys.exit()
        
sha1 = hashlib.sha1()        
sha1.update((K + NB + NA).encode('utf-8'))
ssk = sha1.hexdigest()

while True:
    data = input("Enter the message: ")
    if data == "exit":
        client_socket.sendto(data.encode('utf-8'), ADDR)
        print('Disconnected from the server.')
        break
    
    #sign via ssk
    sha1_a = hashlib.sha1()
    sha1_a.update((ssk + data).encode('utf-8'))
    h = sha1_a.hexdigest()
    #encode via RC4
    key = bytes(ssk, encoding='utf-8')
    SKE = ARC4.new(key)
    C = str(base64.b64encode(SKE.encrypt((data+"^"+h).encode('utf-8'))),'utf-8')
    client_socket.sendto(C.encode('utf-8'), ADDR)
    
    #decode via RC4
    reply, addr = client_socket.recvfrom(1024) 
    C = reply.decode('utf-8')
    key = bytes(ssk, encoding='utf-8')
    SKE = ARC4.new(key)
    P = str(SKE.decrypt(base64.b64decode(C)),'gbk')
    p = P.split('^')
    m = p[0]
    h_s = p[1]

    #verify the message
    sha1_b = hashlib.sha1()
    sha1_b.update((ssk + m).encode('utf-8'))
    h_c = sha1_b.hexdigest()
    if h_c == h_s:
        print('message from '+name_s+' : '+m)
    else:
        print('Decryption Error!')
        print(h_c)
        print(h_s)
        print(m)
    
client_socket.close()
