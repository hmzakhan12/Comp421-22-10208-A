import ast
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

#Generating Key
main_key=RSA.generate(4096)

#Storing Public key in file named 'Public_key.pem'
file=open('Public_key.pem','wb')
file.write(main_key.publickey().exportKey('PEM'))
file.close()

#Storing Private key in file named 'Private_key.pem'
file=open('Private_key.pem','wb')
file.write(main_key.exportKey('PEM'))
file.close()

#Encryption using RSA
file1=open('Public_key.pem','r')
pb_key=RSA.importKey(file1.read())
msg=input("Enter message to encrypt: ") #taking input for encryption
encryptor=PKCS1_OAEP.new(pb_key)
enc_message=encryptor.encrypt(bytes(msg,'utf-8'))
print("Encrypted message is: ",enc_message)
file1.close()

#Decryption using RSA
file2=open('Private_key.pem','r')
pr_key=RSA.importKey(file2.read())
msg=input("Enter message to decrypt: ")#taking input for decryption
decryptor=PKCS1_OAEP.new(pr_key)
dec_message=decryptor.decrypt(ast.literal_eval(str(msg)))
print("Decrypted message is: ",dec_message)
file2.close()




