UDP Communication encryption chat software version 1.0

Read the following information before running the program:
1. Initial username of client is 'Bob', the password is '123456'.
2. To create the new user, please add the username and password in password.csv file which in server's directory. You can add any users as you want. 
3. Initial key pair of server has already generated. If you feel unsafe anymore, please run key_generate.py file to get the new key pairs. Do not forget copy the public.pem file to client directory which includes public key of server. 
4. Please run the server first before running the client. And run server.py and client.py in different terminals.
5. After running client, you will be asked to input username, then password. If they are incorrect, the client will terminate immediately, server will go back to beginning and waiting for next user.
6. After connection okey, you can chat with each other.
7. Type 'exit' on client side to disconnect, and program will terminate.
8. If pk does not match on client side, please re-copy the public.pem file from server directory to client directory.
-----------------------------------------------------------------------------

About the server and client: First, they exchanged keys via simple interactions. And client send password encrypted using the RSA algorithm to server. After checking identification of each other. Second, they communicate under RC4 encryption which using shared secret key. They also sign the message using shared secret key. This key is generated while they doing the checking step. And it is one-time key. 
User cannot see the encrypt and decrypt process while chatting. It is processed automatically. The plaintext will display on screen. 
