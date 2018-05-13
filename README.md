# Datajack Proxy
Datajack Proxy a tool to intercept non-HTTP traffic between a native application and a server. This would allow for communications interception and modification, even if encryption and certificate pinning were in use. This is done by hooking the application and intercepting calls to common socket and TLS libraries, and reading the data prior to encryption (for outbound) and after decryption (for inbound).

This is accomplished by injecting JavaScript into the native process using the [Frida API](https://www.frida.re/).

## Features
* Inject into process
  * Linux (using OpenSSL)
    *kTLS in Linux 4.13+ (TODO)
  * MacOS (TODO)
  * Windows (schannel) (TODO)
  * iOS (TODO)
  * Android (TODO)
* Read data prior to outbound encryption
* Write data prior to outbound encryption (TODO)
* Read data after inbound decryption (TODO)
* Write data after inbound decryption (TODO)
* Allow user-defined rules (TODO)
* Allow configuration file for capture rules (TODO)
* File-based traffic capture, edit, and replay (TODO)
* GUI (TODO)


## Usage
**Help**

`python DatajackProxy.py -h`

**Attach** 

Attach to existing process `<pid>`

`python DatajackProxy.py -p <pid>`

Attach to existing process with name `<processName>`

`python DatajackProxy.py -n <processName>`

## Requirements and Installation
* Python 3
* Frida API

1. Assuming you have python 3, install Frida with pip
`pip3 install frida`
2. Clone DataJack Proxy
`git clone git@gitlab.na.nccgroup.com:cwatt/DatajackProxy.git`