#!/usr/bin/python3

from __future__ import print_function
import frida
import sys
import binascii
import argparse
import codecs

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

def print_message(message):
    exit(0)

def on_message(message, data):
    #print(message['payload'])
    if data:
        '''
        # data comes in as type bytes, which is immutable

        # we print the bytes object, which prints as b'DATA'
        print(data[0:])
        write_file("[*] Raw\n")
        write_file(data[0:])

        # caste from immutable bytes to mutable bytearray
        data = bytearray(data)

        # test modify data, using hex. Can be a byte, as shown below, a char string like b'asdf' or even an int, 0-255.
        data[3:4] = b'\x65'

        # Below we print the bytearray as type bytes, but prints as hex
        print(binascii.hexlify(bytearray(data)))
        write_file("[*] hexlify\n")
        write_file(binascii.hexlify(bytearray(data)))

        # Below we print the bytearray data as a string, but appears as hex
        stringVersion = ''.join('{:02x}'.format(x) for x in data)
        print(stringVersion)
        write_file("[*] stringFormat\n")
        write_file(stringVersion)

        # Below we print each byte with spacing!
        breakOn = 2 #break string every 2 characters, to get hex bytes.
        listVersion = [stringVersion[i:i+breakOn] for i in range(0, len(stringVersion), breakOn)]
        print(listVersion)
        #write_file("[*] cut-on-twos\n")
        #write_file([stringVersion[i:i+breakOn] for i in range(0, len(stringVersion), breakOn)])
        '''
        print_bytes(data)

        return 0
    else:
        print(message)

def get_user_input():
    userInput = input("Enter byte string (I.E. \\xaa\\xbb):")
    return(string_to_bytes(userInput))

def write_file(message):
    fileMode = 'a+'
    if isinstance(message, str):
        fileMode = 'a+'
    elif isinstance(message, bytes):
        fileMode = 'ab+'
    with open('../testfile', fileMode) as f:
        read_data = f.read()
        print("[*] reading from testfile")
        print(read_data)
        f.write(message)
        f.close()
    with open('../testfile', 'a') as f:
        f.write('\n')
        f.close()
    return 0

def string_to_bytes(stringToBytes):
    newBytes = codecs.decode(stringToBytes, 'unicode_escape')
    return(newBytes)

def bytes_to_string(in_bytes):
    resp = []
    for x in in_bytes:
        out = hex(x)[2:]
        if x < 10:
            out = '0' + out
        resp.append(out)
    return resp

def bytes_to_human_lines(in_bytes, length=16):
    byteString = bytes_to_string(in_bytes)
    return [byteString[x:x+length] for x in range(0, len(byteString), length)]

def print_bytes(in_bytes, length=16):
    print("          0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 0123456789ABCDEF")
    lines = bytes_to_human_lines(in_bytes, length)
    for j in range(len(lines)):
        byte_index = j * 16
        readable = ''
        for c in lines[j]:
            byte = int(c, 16)
            if byte < 128:
                readable += chr(byte)
            else:
                readable += '.'
        output = hex(byte_index)[2:].zfill(8) + ' ' + ' '.join(lines[j])
        output += ' ' * (56 - len(output))
        print(output, readable)

def read_byte_string(byteString):
    hex_list = byteString.split()
    return bytes([int(x, 16) for x in hex_list])

if __name__ == "__main__":
    main()
    exit('How did you reach this branch?')