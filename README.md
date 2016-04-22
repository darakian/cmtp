# CMTP
The Cipher Mail Transport Protocol (CMTP) is a secure alternative to SMTP. CMTP is a research protocol and is currently at version: <1
## Design
CMTP aims to work as a secure replacement for the simple mail transport protocol (SMTP) in modern email systems. SMTP is a plaintext protocol with an awkward interface used to transport email between users on disparate domains. CMTP takes inspiration from the OpenPGP system, but makes keypairs mandatory in order to enable confidential messaging as a default. Further CMTP automates key exchange in order to maintain the usability expected of email. Work is done in three parts:  
Formal Documents  
The CMTP reference server (cmtpd)
The CMTP reference client (Shorebird)
## cmtpd
A reference implementation for a CMTP server.  
__status__: Currently under active development and in initial alpha state.  
__notes__: Will return local keys. Will not return remote keys.
## Shorebird
A reference implementation for a cmtp client  
__status__: Currently under active development.
