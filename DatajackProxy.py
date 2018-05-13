#!/usr/bin/python3

from __future__ import print_function
import frida
import sys
import binascii
import argparse

def main():
    parser = argparse.ArgumentParser()
    #parser.add_argument('help', metavar='h', type=str, help='The help flag')
    connectToProcessGroup = parser.add_mutually_exclusive_group()
    connectToProcessGroup.add_argument('-p', '--pid', help='pid to attach to', type=int)
    connectToProcessGroup.add_argument('-n', '--name', help='process name to attach to', type=str)
    args = parser.parse_args()

    if args.pid:
        attach(args.pid)
    elif args.name:
        attach(args.name)

    exit(0)


def help():
    exit(0)

def attach(processToAttach):
    print("[*] Attaching to " + str(processToAttach))
    session = frida.attach(processToAttach)

    script = session.create_script("""
    functionPointer = Module.findExportByName(null, "SSL_write");
    console.log(ptr(functionPointer));
    Interceptor.attach(ptr(functionPointer), {
        onEnter: function(args) {
            send(args[2].toInt32());
            send(ptr(args[1]));
            var buf = Memory.readByteArray(ptr(args[1]), args[2].toInt32());
            console.log(typeof(buf));
            send(args[2].toInt32(), buf);

            
        }
    });
    """)
    print(script.on('message', on_message))
    script.load()
    sys.stdin.read()

    #session = frida.attach("opensslclient")
    #
    #script = session.create_script("""
    #functionPointer = Module.findExportByName(null, "SSL_write");
    #console.log(ptr(functionPointer));
    #Interceptor.attach(ptr(functionPointer), {
        #onEnter: function(args) {
            #send(args[2].toInt32());
            #send(ptr(args[1]));
            #var buf = Memory.readByteArray(ptr(args[1]), args[2].toInt32());
            #console.log(typeof(buf));
            #send(args[2].toInt32(), buf);
    #
    #        
        #}
    #});
    #""")

    exit(0)

def printMessage(message):
    exit(0)

def on_message(message, data):
    #print(message['payload'])
    if data:
        # data comes in as type bytes, which is immutable

        # we print the bytes object, which prints as b'DATA'
        print(data[0:])

        # caste from immutable bytes to mutable bytearray
        data = bytearray(data)

        # test modify data, using hex. Can be a byte, as shown below, a char string like b'asdf' or even an int, 0-255.
        data[3:4] = b'\x65'

        # Below we print the bytearray as type bytes, but prints as hex
        print(binascii.hexlify(bytearray(data)))

        # Below we print the bytearray data as a string, but appears as hex
        stringVersion = ''.join('{:02x}'.format(x) for x in data)
        print(stringVersion)

        # Below we print each byte with spacing!
        breakOn = 2 #break string every 2 characters, to get hex bytes.
        print([stringVersion[i:i+breakOn] for i in range(0, len(stringVersion), breakOn)])


        return 0
    else:
        print(message)

if __name__ == "__main__":
    main()
    exit('How did you reach this branch?')