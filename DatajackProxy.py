#!/usr/bin/python3

from __future__ import print_function
from queue import *
from threading import Thread
import threading
from tempfile import mkstemp
#import tempfile
import time
import sys
import frida
import binascii
import argparse
import webbrowser
import subprocess
import random
import codecs
import os
import base64

block = True
hexLineEnd = "[*] Edit hex above. Save and quit to make changes.\n"
queueFridaBuffers = Queue(maxsize=0)
queueUserInput = Queue(maxsize=0)
num_threads = 2

def attach(queueFridaBuffers, queueUserInput, processToAttach):
    mythread = threading.currentThread()
    print("[*] Attaching to " + str(processToAttach))
    #print("[FridaThread]", mythread.getName(), ":", "blarg")
    session = frida.attach(processToAttach)

    global script

    script = session.create_script("""
    
    ;(function(root) {
    var freeExports = typeof exports == 'object' && exports;
    var freeModule = typeof module == 'object' && module &&
        module.exports == freeExports && module;
    var freeGlobal = typeof global == 'object' && global;
    if (freeGlobal.global === freeGlobal || freeGlobal.window === freeGlobal) {
        root = freeGlobal;
    }
    var InvalidCharacterError = function(message) {
        this.message = message;
    };
    InvalidCharacterError.prototype = new Error;
    InvalidCharacterError.prototype.name = 'InvalidCharacterError';
    var error = function(message) {
        throw new InvalidCharacterError(message);
    };
    var TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var REGEX_SPACE_CHARACTERS = /[\\t\\n\\f\\r ]/g;
    var decode = function(input) {
        input = String(input)
            .replace(REGEX_SPACE_CHARACTERS, '');
        var length = input.length;
        if (length % 4 == 0) {
            input = input.replace(/==?$/, '');
            length = input.length;
        }
        if (
            length % 4 == 1 ||
            /[^+a-zA-Z0-9/]/.test(input)
        ) {
            error(
                'Invalid character: the string to be decoded is not correctly encoded.'
            );
        }
        var bitCounter = 0;
        var bitStorage;
        var buffer;
        var output = '';
        var position = -1;
        while (++position < length) {
            buffer = TABLE.indexOf(input.charAt(position));
            bitStorage = bitCounter % 4 ? bitStorage * 64 + buffer : buffer;
            if (bitCounter++ % 4) {
                output += String.fromCharCode(
                    0xFF & bitStorage >> (-2 * bitCounter & 6)
                );
            }
        }
        return output;
    };
    var encode = function(input) {
        input = String(input);
        if (/[^\\0-\\xFF]/.test(input)) {
            error(
                'The string to be encoded contains characters outside of the ' +
                'Latin1 range.'
            );
        }
        var padding = input.length % 3;
        var output = '';
        var position = -1;
        var a;
        var b;
        var c;
        var d;
        var buffer;
        var length = input.length - padding;
        while (++position < length) {
            a = input.charCodeAt(position) << 16;
            b = input.charCodeAt(++position) << 8;
            c = input.charCodeAt(++position);
            buffer = a + b + c;
            output += (
                TABLE.charAt(buffer >> 18 & 0x3F) +
                TABLE.charAt(buffer >> 12 & 0x3F) +
                TABLE.charAt(buffer >> 6 & 0x3F) +
                TABLE.charAt(buffer & 0x3F)
            );
        }
        if (padding == 2) {
            a = input.charCodeAt(position) << 8;
            b = input.charCodeAt(++position);
            buffer = a + b;
            output += (
                TABLE.charAt(buffer >> 10) +
                TABLE.charAt((buffer >> 4) & 0x3F) +
                TABLE.charAt((buffer << 2) & 0x3F) +
                '='
            );
        } else if (padding == 1) {
            buffer = input.charCodeAt(position);
            output += (
                TABLE.charAt(buffer >> 2) +
                TABLE.charAt((buffer << 4) & 0x3F) +
                '=='
            );
        }
        return output;
    };
    var base64 = {
        'encode': encode,
        'decode': decode,
        'version': '0.1.0'
    };
    if (
        typeof define == 'function' &&
        typeof define.amd == 'object' &&
        define.amd
    ) {
        define(function() {
            return base64;
        });
    }   else if (freeExports && !freeExports.nodeType) {
        if (freeModule) { // in Node.js or RingoJS v0.8.0+
            freeModule.exports = base64;
        } else { // in Narwhal or RingoJS v0.7.0-
            for (var key in base64) {
                base64.hasOwnProperty(key) && (freeExports[key] = base64[key]);
            }
        }
    } else { // in Rhino or a web browser
        root.base64 = base64;
    }
    }(this));

    functionPointer = Module.findExportByName(null, "SSL_write");
    Interceptor.attach(ptr(functionPointer), {
        onEnter: function(args) {
            var buf = Memory.readByteArray(ptr(args[1]), args[2].toInt32());
            var ruleAndLength = "Client --> Server, " + args[2].toInt32().toString() + " byte message.";
            send(ruleAndLength, buf);
            var userResponse = recv('input', function(value) {
                //args[1] = ptr(value.payload);
                //TODO Update this function to decode the buffer, then put the buffer back in place of the openSSL argument.
                console.log(value.payload);
                var decodedPayload = base64.decode(value.payload);
                console.log(decodedPayload);
            });
            userResponse.wait();
        }
    });
    """)
    script.on('message', on_message)
    script.load()
    while block:
        time.sleep(1)

    exit(0)

waiting = {}
fridaBufferId = 1000000

def on_message(message, data):
    global fridaBufferId
    global script
    checkBuffers = True
    currentFridaBufferId = fridaBufferId
    fridaBufferId += 1
    if data:
        print(message['payload'])
        print_bytes_for_ui(data)
        waiting[currentFridaBufferId] = None
        queueFridaBuffers.put((currentFridaBufferId, data))
        #while(waiting[currentFridaBufferId] is None):
        #   time.sleep(1)
        #new_data = waiting[currentFridaBufferId]
        #del waiting[currentFridaBufferId]
        while(checkBuffers):
            checkId, encodedBuffer = queueUserInput.get()
            if(checkId is currentFridaBufferId):
                checkBuffers = False
                script.post({'type': 'input', 'payload': encodedBuffer})
            else:
                queueUserInput.put((checkId, encodedBuffer))
                time.sleep(1)
        return 0
    else:
        print(message)

def string_to_bytes(stringToBytes):
    newBytes = codecs.decode(stringToBytes, 'unicode_escape')
    return(newBytes)

def select_os(osSelection):
    if(osSelection == "determine"):
        osSelection = sys.platform
    elif(osSelection == "linux"):
        osSelection = "linux"
    elif(osSelection == "mac"):
        osSelection = "darwin"
    elif(osSelection == "windows"):
        osSelection = "win32"
    else:
        osSelection = "linux"

    return(osSelection)

def user_input_thread(queueFridaBuffers, queueUserInput):
    print("[*] Starting user_input_thread")
    while True:
        print("[*] In user input loop")
        if queueUserInput.empty():
            willEdit = will_user_edit()
            #queueUserInput.put(willEdit)
        pass

def print_bytes_for_ui(inBytes, length=16):
    print("          0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F 0123456789ABCDEF")
    lines = bytes_to_human_lines(inBytes, length)
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

def bytes_to_human_lines(inBytes, length=16):
    byteString = bytes_to_string(inBytes)
    return [byteString[x:x+length] for x in range(0, len(byteString), length)]

def bytes_to_string(inBytes):
    resp = []
    for x in inBytes:
        out = hex(x)[2:]
        if x < 10:
            out = '0' + out
        resp.append(out)
    return resp

def will_user_edit():
    print("[*] Starting will_user_edit")
    print("Edit Packet? Y/n")
    userInput = input()
    if(userInput.lower() == "n" or userInput.lower() == "no"):
        userInput = "n"
    else:
        userInput = "y"
    return(userInput)

def make_bytes_for_temp_file(inBytes, length=16):
    output = ""
    blockOfHexBytes = ""
    readable = ""
    readableSizePerLine = 0
    lines = bytes_to_human_lines(inBytes, length)
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
        blockOfHexBytes += "\n"
    appendOldBytes = hexLineEnd + "[*] Original bytes were:\n" + blockOfHexBytes
    output += blockOfHexBytes + appendOldBytes + "[*] ASCII was:\n" + readable
    return(output)

def edit_bytes_in_temp_file(byteString):
    bytesFromFile = byteString
    try:
        editor = os.getenv("EDITOR")
        if editor:
            print(editor)
        else:
            editor = 'vim'
    finally:
        pass

    tempFileDescriptor, tempFilePath = mkstemp(text=True)
    try:
        with os.fdopen(tempFileDescriptor, 'r+') as tmp:
            tmp.write(byteString)
            tmp.flush()
            os.fsync(tmp.fileno())
            #TODO: Make the arguments work for editors other than Vim
            editProc = subprocess.Popen([editor, '-f', '-o', tempFilePath], close_fds=True, stdout=None)
            editProc.communicate()
            bytesFromFile = ""
            tmp.seek(0)
            for line in tmp:
                if(line in hexLineEnd):
                    break
                else:
                    bytesFromFile += line
    finally:
        os.remove(tempFilePath)

    return(bytesFromFile)

def make_buffer_from_file(multiLineByteString):
    stringToEdit = "".join(multiLineByteString.splitlines()).replace(" ", "")
    newBuffer = codecs.decode(stringToEdit, "hex")
    encodedBuffer = base64.b64encode(newBuffer)
    encodedBuffer = encodedBuffer.decode()
    return(encodedBuffer)
    #print(newBuffer)

def read_byte_string(byteString):
    hex_list = byteString.split()
    return bytes([int(x, 16) for x in hex_list])

def main():
    print("[*] Starting MAIN")

    # Default to Linux OS
    os = 'linux'
    hasUserGivenInput = False
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--os", help="Set OS to either 'linux', 'windows', or 'mac'", type=str, choices=["linux", "windows", "mac"])
    connectToProcessGroup = parser.add_mutually_exclusive_group()
    connectToProcessGroup.add_argument("-p", "--pid", help="pid to attach to", type=int)
    connectToProcessGroup.add_argument("-n", "--name", help="process name to attach to", type=str)

    args = parser.parse_args()

    # Select OS
    if(args.os):
        os = select_os(args.os)
    else:
        os = select_os("determine")

    if(args.pid):
        fridaThread = Thread(target=attach, args=(queueFridaBuffers, queueUserInput, args.pid))
    elif(args.name):
        fridaThread = Thread(target=attach, args=(queueFridaBuffers, queueUserInput, args.name))
    else:
        exit("Please provide either a PID (-p) or process name (-n)")

    fridaThread.setDaemon(True)
    fridaThread.start()

    while True:
        if not queueFridaBuffers.empty():
            bufferId, fridaBuffer = queueFridaBuffers.get()
            willEdit = will_user_edit()
            if(willEdit == "y"):
                encodedBuffer = make_buffer_from_file(edit_bytes_in_temp_file(make_bytes_for_temp_file(fridaBuffer)))
                queueUserInput.put((bufferId, encodedBuffer))
        else:
            pass

    exit(0)

if __name__ == "__main__":
    main()
    exit('How did you reach this branch?')