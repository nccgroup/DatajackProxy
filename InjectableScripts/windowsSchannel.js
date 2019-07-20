try 
        {
            functionPointer_Schannel_EncryptMessage = Module.findExportByName(null, "EncryptMessage");
            Interceptor.attach(ptr(functionPointer_Schannel_EncryptMessage), {
                onEnter: function(args) {
                    if(args[3].toInt32() != 0)
                    {
                        console.log("Arg 3 was " + args[3]);
                    }
                    else 
                    {
                        /*console.log("[DJP] arg 0 was " + args[0]);
                        console.log("[DJP] arg 1 was " + args[1]);
                        console.log("[DJP] arg 2 was " + args[2]);
                        console.log("[DJP] arg 3 was " + args[3]);*/
                        this.pMessage = args[2];

                        //Read the cBuffers (count of buffers) from the SecBufferDesc struct. This has always been a 32-bit unsigned Long so far as I've seen. This is the number of buffers (messages) that are to be encrypted.
                        this.long_cBuffers_SecBufferDesc = Memory.readULong(ptr(this.pMessage.toInt32() + 4));

                        this.pointer_pBuffers = Memory.readPointer(ptr(this.pMessage.toInt32() + 8));

                        for (i = 0; i < this.long_cBuffers_SecBufferDesc; i++)
                        {
                            //cbBuffer is the length of the buffer to encrypt, this is at offset 0 in the SecBuffer structure.
                            this.data_cbBuffer = Memory.readULong(ptr(this.pointer_pBuffers.toInt32() + (i * 12) + 0));

                            //BufferType is the type of buffer held in this message. Buffer type of 1, or SECBUFFER_DATA contains common data. This is at offset 4 in the SecBuffer structure.
                            this.data_BufferType = Memory.readULong(ptr(this.pointer_pBuffers.toInt32() + (i * 12) + 4));
                            //console.log("[DJP] bufferType: " + this.data_BufferType);

                            //pvBuffer is the actual buffer char *, and we add the length from cbBuffer. This is at offset 8 in the SecBuffer structure.
                            this.pointer_pvBuffer = Memory.readPointer(ptr(this.pointer_pBuffers.toInt32() + (i * 12) + 8));
                            this.data_pvBuffer = Memory.readByteArray(this.pointer_pvBuffer, this.data_cbBuffer);

                            // Check if this is a SECBUFFER_DATA message, otherwise we ignore it.
                            if(this.data_BufferType == 1)
                            {
                                //console.log("[DJP] cbBuffer length: " + this.data_cbBuffer);
                                this.ruleAndLength = "Client --> Server, Message " + (i + 1) + " of " + this.long_cBuffers_SecBufferDesc + ", " + Memory.readULong(ptr(this.pointer_pBuffers.toInt32() + (i * 12))) + " byte message.";

                                // Make sure that the message has some bytes in it, otherwise we ignore it. If not, DJP hangs waiting for a user response.
                                if(this.data_cbBuffer == 0)
                                {
                                    console.log("[DJP] This message is 0 bytes, nothing to edit.")
                                }
                                else
                                {
                                    send(this.ruleAndLength, this.data_pvBuffer);

                                    var userResponse = recv('input', function(value) {
                                    if(value.payload != "DJP*NoEdit")
                                    {
                                        var decodedPayload = base64.decode(value.payload);
                                        editedBufferFromUser = decodedStringToArrayBuffer(decodedPayload);
                                        newlyAllocBuffer = Memory.alloc(decodedPayload.length);
                                        Memory.writeByteArray(newlyAllocBuffer, editedBufferFromUser);
                                        newArgLength = new Int64(decodedPayload.length);

                                        Memory.writeULong((ptr(this.pointer_pBuffers.toInt32() + (i * 12))), newArgLength);
                                        Memory.writePointer(ptr(this.pointer_pBuffers.toInt32() + (i * 12) + 8), newlyAllocBuffer);

                                        args[2] = ptr(newArgLength);
                                        args[1] = newlyAllocBuffer;
                                    }
                                    });
                                    userResponse.wait();
                                }
                            }
  
                        }

                    }
                } 
            });
        }
        catch(err)
        {
            console.log("[injectable-windowsSchannel] Could not find function EncryptMessage");
        }