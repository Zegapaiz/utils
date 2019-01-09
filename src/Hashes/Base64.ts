/**
* @member Hashes
* @class Base64
* @constructor
*/
import { utf8Decode, utf8Encode } from './Common'
    
export default class Base64 {
    // private properties
    private tab:string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    private pad:string = '=' // default pad according with the RFC standard
    // private url:boolean = false // URL encoding support @todo
    private utf8:boolean = true // by default enable UTF-8 support encoding

    // public method for encoding
    public encode (input:any) {
        var i, j, triplet,
            output = '',
            len = input.length;

        this.pad = this.pad || '=';
        input = (this.utf8) ? utf8Encode(input) : input;

        for (i = 0; i < len; i += 3) {
            triplet = (input.charCodeAt(i) << 16) | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
            for (j = 0; j < 4; j += 1) {
                if (i * 8 + j * 6 > len * 8) {
                    output += this.pad;
                } else {
                    output += this.tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
                }
            }
        }
        return output;
    };

    // public method for decoding
    public decode (input:any) {
        // var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
        var i, o1, o2, o3, h1, h2, h3, h4, bits, ac,
            dec = '',
            arr = [];
        if (!input) {
            return input;
        }

        i = ac = 0;
        input = input.replace(new RegExp('\\' + this.pad, 'gi'), ''); // use '='
        //input += '';

        do { // unpack four hexets into three octets using index points in b64
            h1 = this.tab.indexOf(input.charAt(i += 1));
            h2 = this.tab.indexOf(input.charAt(i += 1));
            h3 = this.tab.indexOf(input.charAt(i += 1));
            h4 = this.tab.indexOf(input.charAt(i += 1));

            bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

            o1 = bits >> 16 & 0xff;
            o2 = bits >> 8 & 0xff;
            o3 = bits & 0xff;
            ac += 1;

            if (h3 === 64) {
                arr[ac] = String.fromCharCode(o1);
            } else if (h4 === 64) {
                arr[ac] = String.fromCharCode(o1, o2);
            } else {
                arr[ac] = String.fromCharCode(o1, o2, o3);
            }
        } while (i < input.length);

        dec = arr.join('');
        dec = (this.utf8) ? utf8Decode(dec) : dec;

        return dec;
    };

    // set custom pad string
    public setPad (str:string) {
        this.pad = str ||this. pad;
        return this;
    };
    // set custom tab string characters
    public setTab (str:string) {
        this.tab = str || this.tab;
        return this;
    };
    public setUTF8 (bool:boolean) {
        if (typeof bool === 'boolean') {
            this.utf8 = bool;
        }
        return this;
    };
}