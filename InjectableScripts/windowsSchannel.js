try 
        {
            functionPointer_Schannel_EncryptMessage = Module.findExportByName(null, "EncryptMessage");
            Interceptor.attach(ptr(functionPointer_Schannel_EncryptMessage), {
                onEnter: function(args) {
                    console.log("Entered EncryptMessage!");
                    if(args[3].toInt32() != 0)
                    {
                        console.log("Arg 3 was " + args[3]);
                    }
                    else 
                    {
                        console.log("pMessage Pointer:" + args[2].toString());
                        this.pMessage = args[2];

                        //Read the cBuffers (count of buffers) from the SecBufferDesc struct. This has always been a 32-bit unsigned Long so far as I've seen. This is the number of buffers (messages) that are to be encrypted.
                        this.long_cBuffers_SecBufferDesc = Memory.readULong(ptr(this.pMessage.toInt32() + 4));
                        //this.ruleAndLength = "Client --> Server, X byte message.";
                        this.ruleAndLength = "Client --> Server, " + this.long_cBuffers_SecBufferDesc + " byte message.";
                        send(this.ruleAndLength, this.struct_pMessage_SecBufferDesc);
                    }
                    /*    
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
                    
                    console.log("Entered EncryptMessage!");
                    });
                    userResponse.wait();
                    */
                } 
            });
        }
        catch(err)
        {
            console.log("[injectable-windowsSchannel] Could not find function EncryptMessage");
        }
