# The Cipher Mail Project
Email is the de facto standard for internet communications, it is a requirement nearly any web resource available and it sucks. The Simple Mail Transfer Protocol (SMTP) is the fundamental mechanism by which email is passed on the internet today, but was designed in an era before the personal computer, before the disposable computer and critically before internet communications became important. The Cipher Mail Project is working toward a secure by default email implementation. This repository contains the replacement for SMTP; CMTP.
## CMTP
The Cipher Mail Transport Protocol (CMTP) is a secure alternative to SMTP which aims to raise floor on internet communications. The goal of CMTP is not to push the envelope of what is possible, but rather to provide a new standard which SMTP systems and users can easily transition to. Currently CMTP is a research protocol and is at version: 0.01
## Design Goals
* Coexist with SMTP on port 25
* Encrypt all mail by default
* Transparent key exchange
* Open, federated mail network
* Recoverable client keys (by the client)

## Protocol Design
The coexistence goal has lead CMTP to be an ASCII command driven protocol with commands which are nonintersecting with SMTP. These commands can be seen in detail in the CMTP docs. Encrypted mail by default with transpant key exchange has lead CMTP to mandate keypairs and to have a protocol command for key retrieval. The open federated network goal has lead to possible insecurity by accepting unknown keys, but has also lead to a greater role of the mail server in federating trust. Mail have keys and servers sign all communications so that future communications are known to be valid.

## Current work and challenges
### Spam
Encrypting all mail presents a problem for traditional spam prevention methods which rely on content analysis.
### Mail delivery
An analog to IMAP is needed to complete the cipher mail ecosystem and is being drafted.
## Reference code
Work is done in three parts:  
Formal Documents  
The CMTP reference server (cmtpd)  
The CMTP reference client (Shorebird)

## Build Instructions
### Linux
Ensure you have the following dependencies installed
* libconfuse
* libsodium
* ldns

In Fedora linux the packages are libconfuse-devel, libsodium-devel, and ldns-devel. Once the dependencies are installed simply issue
```
make
```

### MacOS
Not yet supported

### Windows
Probably won't be supported
