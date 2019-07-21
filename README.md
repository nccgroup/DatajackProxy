# Datajack Proxy
Datajack Proxy a tool to intercept non-HTTP traffic between a native application and a server. This would allow for communications interception and modification, even if encryption and certificate pinning were in use. This is done by hooking the application and intercepting calls to common socket and TLS libraries, and reading the data prior to encryption (for outbound) and after decryption (for inbound).

This is accomplished by injecting JavaScript into the native process using the [Frida API](https://www.frida.re/).

## Features
* Inject into process
  * Linux (Using OpenSSL SSL_Read and SSL_Write)
  * Windows (Using schannel EncryptMessage [DecryptMessage todo])
* Read/write data prior to outbound encryption on Linux
* Read/write data after inbound decryption on Linux
* Read data prior to outbound encryption on Windows (write is todo)

Note: Currently only Linux and Windows are supported. Linux supports the OpenSSL calls SSL_Write and SSL_Read.

## Usage
**Help**

`python DatajackProxy.py -h`

**Attach** 

Attach to existing process `<pid>`

`python DatajackProxy.py -p <pid>`

Attach to existing process with name `<processName>`

`python DatajackProxy.py -n <processName>`

Attach to Windows process with name `OUTLOOK.EXE`

`python DatajackProxy.py -n OUTLOOK.EXE -o windows`

## Requirements and Installation
* Python 3
* Frida API

1. Assuming you have python 3, install Frida with pip
`pip3 install frida`
2. Clone DataJack Proxy
`git clone git@gitlab.na.nccgroup.com:cwatt/DatajackProxy.git`