try 
        {
            functionPointer_OpenSSL_SSL_write = Module.findExportByName(null, "SSL_write");
            console.log("[injectable-linuxOpenSSLAndSocketWrite] Hooked function 'SSL_write'");
            Interceptor.attach(ptr(functionPointer_OpenSSL_SSL_write), {
                onEnter: function(args) {
                    var buf = Memory.readByteArray(ptr(args[1]), args[2].toInt32());
                    var ruleAndLength = "Client --> Server, " + args[2].toInt32().toString() + " byte message.";
                    send(ruleAndLength, buf);
                    var userResponse = recv('input', function(value) {
                        if(value.payload != "DJP*NoEdit")
                        {
                            var decodedPayload = base64.decode(value.payload);
                            editedBufferFromUser = decodedStringToArrayBuffer(decodedPayload);
                            newlyAllocBuffer = Memory.alloc(decodedPayload.length);
                            Memory.writeByteArray(newlyAllocBuffer, editedBufferFromUser);
                            newArgLength = new Int64(decodedPayload.length);
                            args[2] = ptr(newArgLength);
                            args[1] = newlyAllocBuffer;
                        }
                    });
                    userResponse.wait();
                } 
            });
        }
        catch(err)
        {
            console.log("[injectable-linuxOpenSSLAndSocketWrite] Could not find function 'SSL_write'");
        }

        if (!functionPointer_OpenSSL_SSL_write)
        {
            try
            {
                functionPointer_LinuxSocket_write = Module.findExportByName(null, "write");
                console.log("[injectable-linuxOpenSSLAndSocketWrite] Hooked function 'write'");
                Interceptor.attach(ptr(functionPointer_LinuxSocket_write), {
                    onEnter: function(args) {
                        var buf = Memory.readByteArray(ptr(args[1]), args[2].toInt32());
                        // Check args[0] to ensure it is not a "1", which is the argument for local sockets, rather than network sockets (which are 3).
                        if(Object.is(args[0].toInt32(), 3))
                        {
                            var ruleAndLength = "Client --> Server, " + args[2].toInt32().toString() + " byte message.";
                            send(ruleAndLength, buf);
                            var userResponse = recv('input', function(value) {
                                if(value.payload != "DJP*NoEdit")
                                {
                                    var decodedPayload = base64.decode(value.payload);
                                    editedBufferFromUser = decodedStringToArrayBuffer(decodedPayload);
                                    newlyAllocBuffer = Memory.alloc(decodedPayload.length);
                                    Memory.writeByteArray(newlyAllocBuffer, editedBufferFromUser);
                                    newArgLength = new Int64(decodedPayload.length);
                                    args[2] = ptr(newArgLength);
                                    args[1] = newlyAllocBuffer;
                                }
                            });
                            userResponse.wait();
                        }
                    }
                });
            }
            catch(err)
            {
                console.log("[injectable-linuxOpenSSLAndSocketWrite] Could not find function 'write'");
            }
        }

        try
        {
            functionPointer_openSSL_SSL_read = Module.findExportByName(null, "SSL_read");
            console.log("[injectable-linuxOpenSSLAndSocketWrite] Hooked function 'SSL_read'");
            Interceptor.attach(ptr(functionPointer_openSSL_SSL_read), {
                onEnter: function(args) {
                    //this.domainNumber = args[0].toInt32();
                    this.bufPointer = args[1];
                    this.bufLength = args[2].toInt32();
                },
                onLeave: function (result) {
                    //if(this.domainNumber == 3)
                    //{
                        originalBufferLength = this.bufLength;
                        this.ruleAndLength = "Server --> Client, " + originalBufferLength.toString() + " byte message.";
                        this.buf_LinuxSocket_read = Memory.readByteArray(ptr(this.bufPointer), originalBufferLength);
                        var originalBufferPointer = this.bufPointer;
                        send(this.ruleAndLength, this.buf_LinuxSocket_read);
                        this.userResponse = recv('input', function(value) {
                            if(value.payload != "DJP*NoEdit")
                            {
                                decodedPayload = base64.decode(value.payload);
                                if(decodedPayload.length > originalBufferLength)
                                {
                                    console.log("Read call edits cannot be longer than original buffer. Truncated to " + originalBufferLength + " bytes.");
                                    decodedPayload = decodedPayload.substring(0, originalBufferLength);
                                }
                                editedBufferFromUser = decodedStringToArrayBuffer(decodedPayload);
                                Memory.writeByteArray(ptr(originalBufferPointer), editedBufferFromUser);
                            }
                        });
                        this.userResponse.wait();
                    //}
                }
            });
        }
        catch(err)
        {
            console.log("[injectable-linuxOpenSSLAndSocketWrite] Could not find function 'SSL_read'");
        }

        if (!functionPointer_openSSL_SSL_read)
        {
            try
            {
                functionPointer_socket_read = Module.findExportByName(null, "read");
                console.log("[injectable-linuxOpenSSLAndSocketWrite] Hooked function 'read'");
                Interceptor.attach(ptr(functionPointer_socket_read), {
                    onEnter: function(args) {
                        this.domainNumber = args[0].toInt32();
                        this.bufPointer = args[1];
                        this.bufLength = args[2].toInt32();
                    },
                    onLeave: function (result) {
                        if(this.domainNumber == 3)
                        {
                            originalBufferLength = this.bufLength;
                            this.ruleAndLength = "Server --> Client, " + originalBufferLength.toString() + " byte message.";
                            this.buf_LinuxSocket_read = Memory.readByteArray(ptr(this.bufPointer), originalBufferLength);
                            var originalBufferPointer = this.bufPointer;
                            send(this.ruleAndLength, this.buf_LinuxSocket_read);
                            this.userResponse = recv('input', function(value) {
                                if(value.payload != "DJP*NoEdit")
                                {
                                    decodedPayload = base64.decode(value.payload);
                                    if(decodedPayload.length > originalBufferLength)
                                    {
                                        console.log("Read call edits cannot be longer than original buffer. Truncated to " + originalBufferLength + " bytes.");
                                        decodedPayload = decodedPayload.substring(0, originalBufferLength);
                                    }
                                    editedBufferFromUser = decodedStringToArrayBuffer(decodedPayload);
                                    Memory.writeByteArray(ptr(originalBufferPointer), editedBufferFromUser);
                                }
                            });
                            this.userResponse.wait();
                        }
                    }
                });
            }
            catch(err)
            {
                console.log("[injectable-linuxOpenSSLAndSocketWrite] Could not find function 'read'");
            }
        }
        