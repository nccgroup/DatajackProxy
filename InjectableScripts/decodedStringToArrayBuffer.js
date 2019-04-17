function decodedStringToArrayBuffer(decodedString)
        {
            var bufferToReturn = new ArrayBuffer(decodedString.length);
            var bufferToReturnView = new Uint8Array(bufferToReturn);
            for (i = 0; i < decodedString.length; i++)
            {
                bufferToReturnView[i] = decodedString.charCodeAt(i);
            }

            return bufferToReturn;
        }
        