# sample-ldap-login
"sample-ldap-login" provides a login form to authenticate users through a LDAP Server.
User should provide username and password and the application should contact the LDAP Server and verify credentials. If authentication succeeds, print a welcome message that includes name and surname of the user, stored respectively in cn and sn attributes.

## Requirements

- Use Java 8 to write your code;
- LDAP Server must have directory entry root “dc=myorg,dc=test” and you should import LDIF file we
provide to you in order to initialize it;
- LDAP connection parameters should be stored in a configuration file that will be located in the same path of the jar file. It must be editable in order to allow connection to another LDAP server populated with the same LDIF file;
- Usernames are stored in uid attribute; passwords are stored and hashed in userpassword attribute and are the same for every user: Password123!

### Bonus features
Improve the application security implementing two-factor authentication.
After a correct authentication, user should provide an OTP in order to access to protected content, as follow:
- OTP should be implemented as TOTP (Time-based One-Time Password), described in RFC6238 (https://tools.ietf.org/html/rfc6238);
- TOTP algorithm parameters should be the following:
- Timestep : 20 seconds;
- OTPlength : 8 digits;
- Hashing algorithm : SHA256
- Secret : base32 encoded and stored in user's LDAP attribute “l”(lowercase L).
- Tests should be executed installing on your smartphone a TOTP generator as FreeOTP Authenticator, scanning a QR code for each user. QR Codes could be generated with your favorite tool and it should include an URL in the following format (specified in https://github.com/google/google-authenticator/wiki/Key-Uri-Format):

```
otpauth://totp/<username>? secret=<secret>&issuer=<indifferente>&algorithm=SHA256&digits=8&period=20
```

# My solution

## Setting up an OpenLDAP Server

In order to try my software, I've set-up a [Debian](https://www.debian.org) distro and I've installed OpenLDAP following [this guide](https://github.com/IntersectAustralia/acdata/wiki/Setting-up-OpenLDAP). **Please note: if you're working on a macOS machine, there's a known bug related to Kerberos** you can find it [here](https://www.openldap.org/lists/openldap-technical/201403/msg00168.html).

### Upload the given dataset
Once the server is up and running, I suggest to use [Apache Directory Studio](http://directory.apache.org/studio/). The interface is very similar to Eclipse and pushing the *ldif* file is super duper easy.

# The software
In this section, I'm going to explain my choices and solutions.

## Overview
### Package diagram:
![alt-text](https://raw.githubusercontent.com/gittubbs/sample-ldap-login/master/resources/uml/ldap_package.jpg?raw=true)
### Class diagram
![alt-text](https://raw.githubusercontent.com/gittubbs/sample-ldap-login/master/resources/uml/diagram.jpg?raw=true)
### How it works?
As you can see, the architecture of this solution is pretty simple.
**Loader** Contains the main method. The first thing it does is to *initialise* a **LDAPConnection** (which is the *abstraction* of the connection torwards the Directory) with the help of **LDAPConnectionProperties** class. Depending on the choice, you can try to bind to OpenLDAP with username, password and OTP or **generate a QR code** for the OTP enrollment.
### Awesome. Did you use any external tool or library?
**YES**. 
- Core connection to OpenLDAP is provided by Java in **javax.naming** package.
- Data format manipulation (Base32 conversion, etc) has been delegated to **Guava** library by Google.
- QRCode generation is made by an external wrapper (you can find [here](https://github.com/johnnymongiat/oath) the github page) for [zxing](https://github.com/zxing/zxing).
- OTP generation and verification has been made from [here](https://github.com/johnnymongiat/oath/tree/master/oath-otp). The original source code has been modified (by me) in order to accept different hashing algorithms.

For this project, I decided to don't use Maven. You can find the dependencies in the *lib* folder.

**Please note:** the *&algorithm=SHA256* directive in the Key Uri is not reconised from Google Authenticator app. I suggest **FreeOTP**.
# Make it run!!!
- Do you have the [latest JRE](http://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html)?
Of course you do!
- Start OpenLDAP server
- Feed the server with the provided ldif file
- create (or modify) the *ldap.prop* file using this format
```
hostname=127.0.0.1
port=389
```
- Download bin/loader.jar
- Open a terminal
- Type
```
java -jar loader.jar
```
- Follow onscreen instructions
- Have fun!