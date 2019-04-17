try 
        {
            functionPointer_Schannel_EncryptMessage = Module.findExportByName(null, "EncryptMessage");
            Interceptor.attach(ptr(functionPointer_Schannel_EncryptMessage), {
                onEnter: function(args) {
                    console.log("Entered EncryptMessage!");
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
            
        }
        