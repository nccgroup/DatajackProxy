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
