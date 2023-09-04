#!/usr/bin/env python
# coding: utf-8

# In[29]:


from socket import *
from Crypto.Cipher import ARC4
import random
import string
import rsa
import hashlib
import base64
import pandas as pd


HOST = ''
PORT = 5555
ADDR = (HOST, PORT)

server_socket = socket(AF_INET,SOCK_DGRAM)
server_socket.bind(ADDR)

while True: #in loop if username or password incorrect
    #1
    print('waiting for connecting...')
    data,addr=server_socket.recvfrom(1024)
    name_c = data.decode('utf-8')
    data,addr=server_socket.recvfrom(1024)
    NB = data.decode('utf-8')
    print(name_c + " is connecting...")
    #2
    NA = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    server_socket.sendto('Alice'.encode('utf-8'), addr)
    server_socket.sendto(NA.encode('utf-8'), addr)
    with open('public.pem') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())
    with open('private.pem') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())
    server_socket.sendto(str(pubkey).encode('utf-8'), addr)
    print('server name and public key sended... ')
    #3
    data,addr=server_socket.recvfrom(1024)
    pw_c = rsa.decrypt(data, privkey).decode('utf-8')  #RSA decode
    data,addr=server_socket.recvfrom(1024)
    K = rsa.decrypt(data, privkey).decode('utf-8')  #RSA decode
    #4
    df = pd.read_csv('password.csv')
    for i in range(len(df)):  #check the username and password
        if str(df['name'][i]) == name_c:
            if str(df['password'][i]) == pw_c:
                server_socket.sendto('Connection Okay'.encode('utf-8'), addr)
                print('connect with ' + name_c)
                break
    else:
        server_socket.sendto('Connection Failed'.encode('utf-8'), addr)
        print('user does not exist or password wrong.')
        continue
    break

sha1 = hashlib.sha1()        
sha1.update((K + NB + NA).encode('utf-8'))
ssk = sha1.hexdigest()
    
while True: 
    data,addr=server_socket.recvfrom(1024)
    C = data.decode('utf-8')
    if C == 'exit':
        print(name_c+' has disconnected.')
        break
        
    #decode via RC4
    key = bytes(ssk, encoding='utf-8')
    SKE = ARC4.new(key)
    P = str(SKE.decrypt(base64.b64decode(C)),'gbk')
    p = P.split('^')
    m = p[0]
    h_c = p[1]

    #verify the message
    sha1_b = hashlib.sha1()
    sha1_b.update((ssk + m).encode('utf-8'))
    h_s = sha1_b.hexdigest()
    if h_s == h_c:
        print('message from '+name_c+' : '+m)
    else:
        print('Decryption Error!')
        
    reply = input("Enter the message: ")
    #sign via ssk
    sha1_a = hashlib.sha1()
    sha1_a.update((ssk + reply).encode('utf-8'))
    h = sha1_a.hexdigest()
    #encode via RC4
    key = bytes(ssk, encoding='utf-8')
    SKE = ARC4.new(key)
    C = str(base64.b64encode(SKE.encrypt((reply+"^"+h).encode('utf-8'))),'utf-8')
    server_socket.sendto(C.encode('utf-8'), addr)
    
    
server_socket.close()


# In[ ]:





# In[ ]:




