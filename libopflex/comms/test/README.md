This directory has certificate and private key files
used for communications library unit tests. These
certificates need to be renewed from time to time. There
will be UT failures due to SSL not being able to decrypt.

Generating a Certificate Authority (CA) Certificate for Self-Signing:

1.   Generate a CA private key:
   **openssl genrsa -des3 -out CA-key.pem 2048**

2.   Generate the root CA certificate.
   **openssl req -new -key CA-key.pem -x509 -days 1000 -out CA-cert.pem** 
(You will be prompted for information which will be incorporated into the certificate, such as Country, City, Company Name, etc. Remember what information you entered as you may get prompted for this information again at a later stage. When asked for an email address, provide the email address of the CA contact)

3.   You will need CA-key.pem and CA-cert.pem from the previous step. 

4.   Generate a new key:
   **openssl genrsa -des3 -out server-key.pem 2048**

5.   Generate a certificate signing request:
   **openssl req -key server-key.pem -new -out signingReq.csr**

6.   Self-sign the certificate using your CA-cert.pem certificate
   **openssl x509 -req -days 365 -in signingReq.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial -out server-cert.pem**

Reference:
https://www.simba.com/products/SEN/doc/Client-Server_user_guide/content/clientserver/configuringssl/signingca.htm

Tested and verified the certs on ubuntu 20.04

