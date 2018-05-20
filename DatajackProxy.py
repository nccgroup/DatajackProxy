#!/usr/bin/python3

from __future__ import print_function
import frida
import sys
import binascii
import argparse
#import codecs
import tempfile

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
        print("Back to Main()")

    exit(0)


def help():
    exit(0)

def attach(processToAttach):
    print("[*] Attaching to " + str(processToAttach))
    session = frida.attach(processToAttach)

    script = session.create_script("""
    functionPointer = Module.findExportByName(null, "SSL_write");
    Interceptor.attach(ptr(functionPointer), {
        onEnter: function(args) {
            var buf = Memory.readByteArray(ptr(args[1]), args[2].toInt32());
            var ruleAndLength = "Client --> Server, " + args[2].toInt32().toString() + " byte message.";
            send(ruleAndLength, buf);          
        }
    });
    """)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

    exit(0)

def on_message(message, data):
    #print(message['payload'])
    if data:
        print(message['payload'])
        print_bytes_for_ui(data)
        #print_bytes_for_temp_file(data)
        return 0
    else:
        print(message)

#def get_user_input():
#    userInput = input("Enter byte string (I.E. \\xaa\\xbb):")
#    return(string_to_bytes(userInput))

def edit_bytes_in_temp_file(byteString):
    f = tempfile.TemporaryFile()
    fp.write(byteString)
    input("Look for file in dir")
    return(newByteString)

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

#def string_to_bytes(stringToBytes):
#    newBytes = codecs.decode(stringToBytes, 'unicode_escape')
#    return(newBytes)

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

def print_bytes_for_ui(in_bytes, length=16):
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

def print_bytes_for_temp_file(in_bytes, length=16):
    output = ''
    blockOfHexBytes = ''
    instructions = '[*] Edit hex below. Save and quit to make changes.\n'
    readable = ''
    readableSizePerLine = 0
    lines = bytes_to_human_lines(in_bytes, length)
    for j in range(len(lines)):
        for c in lines[j]:
            byte = int(c, 16)
            if byte < 128:
                readable += chr(byte)
            else:
                readable += '.'
            if readableSizePerLine >= length - 1:
                readable += '\n'
                readableSizePerLine = 0
            else:
                readableSizePerLine+=1
        blockOfHexBytes += ' '.join(lines[j])
        blockOfHexBytes += '\n'
    appendOldBytes = "[*] End of hex\n[*] Original bytes were:\n" + blockOfHexBytes
    output += instructions + blockOfHexBytes + appendOldBytes + "[*] ASCII was:\n" + readable
    print(output)

def read_byte_string(byteString):
    hex_list = byteString.split()
    return bytes([int(x, 16) for x in hex_list])

if __name__ == "__main__":
    main()
    exit('How did you reach this branch?')