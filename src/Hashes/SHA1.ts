/**
* @class Hashes.SHA1
* @param {Object} [config]
* @constructor
*
* A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined in FIPS 180-1
* Version 2.2 Copyright Paul Johnston 2000 - 2009.
* Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
* See http://pajhome.org.uk/crypt/md5 for details.
*/
import {
    rstr2hex, rstr2b64, utf8Encode, safe_add, bit_rol,
    rstr2any, binb2rstr, rstr2binb
} from './Common'

export default class SHA1 {


    private hexcase: boolean; // hexadecimal output case format. false - lowercase; true - uppercase
    private b64pad: string;// base-64 pad character. Defaults to '=' for strict RFC compliance
    private utf8: boolean; // enable/disable utf8 encoding
    constructor(options?: any) {
        // super(); // 调用父类的 constructor(name)
        // this.options = options
        this.hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false
        this.b64pad = (options && typeof options.pad === 'string') ? options.pad : '='
        this.utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true
    }
    // public methods
    public hex(s: any) {
        return rstr2hex(this.rstr(s), this.hexcase);
    };
    public b64(s: any) {
        return rstr2b64(this.rstr(s), this.b64pad);
    };
    public any(s: any, e: any) {
        return rstr2any(this.rstr(s), e);
    };
    public raw(s: any) {
        return this.rstr(s);
    };
    public hex_hmac(k: any, d: any) {
        return rstr2hex(this.rstr_hmac(k, d), this.hexcase);
    };
    public b64_hmac(k: any, d: any) {
        return rstr2b64(this.rstr_hmac(k, d), this.b64pad);
    };
    public any_hmac(k: any, d: any, e: any) {
        return rstr2any(this.rstr_hmac(k, d), e);
    };
    /**
     * Perform a simple self-test to see if the VM is working
     * @return {String} Hexadecimal hash sample
     * @public
     */
    public vm_test() {
        return this.hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
    };
    /**
     * @description Enable/disable uppercase hexadecimal returned string
     */
    public setUpperCase(a: boolean): object {
        if (typeof a === 'boolean') {
            this.hexcase = a;
        }
        return this;
    };
    /**
     * @description Defines a base64 pad string
     */
    public setPad(a: string): object {
        this.b64pad = a || this.b64pad;
        return this;
    };
    /**
     * @description Defines a base64 pad string
     */
    public setUTF8(a: boolean): object {
        if (typeof a === 'boolean') {
            this.utf8 = a;
        }
        return this;
    };

    // private methods

    /**
     * Calculate the SHA-512 of a raw string
     */

    private rstr(s: any) {
        s = (this.utf8) ? utf8Encode(s) : s;
        return binb2rstr(this.binb(rstr2binb(s), s.length * 8));
    }

    /**
     * Calculate the HMAC-SHA1 of a key and some data (raw strings)
     */

    private rstr_hmac(key: any, data: any) {
        var bkey, ipad, opad, i, hash;
        key = (this.utf8) ? utf8Encode(key) : key;
        data = (this.utf8) ? utf8Encode(data) : data;
        bkey = rstr2binb(key);

        if (bkey.length > 16) {
            bkey = this.binb(bkey, key.length * 8);
        }
        ipad = Array(16), opad = Array(16);
        for (i = 0; i < 16; i += 1) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }
        hash = this.binb(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
        return binb2rstr(this.binb(opad.concat(hash), 512 + 160));
    }

    /**
     * Calculate the SHA-1 of an array of big-endian words, and a bit length
     */

    private binb(x: any, len: any) {
        var i, j, t, olda, oldb, oldc, oldd, olde,
            w = Array(80),
            a = 1732584193,
            b = -271733879,
            c = -1732584194,
            d = 271733878,
            e = -1009589776;

        /* append padding */
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;

        for (i = 0; i < x.length; i += 16) {
            olda = a;
            oldb = b;
            oldc = c;
            oldd = d;
            olde = e;

            for (j = 0; j < 80; j += 1) {
                if (j < 16) {
                    w[j] = x[i + j];
                } else {
                    w[j] = bit_rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                }
                t = safe_add(safe_add(bit_rol(a, 5), this.sha1_ft(j, b, c, d)),
                    safe_add(safe_add(e, w[j]), this.sha1_kt(j)));
                e = d;
                d = c;
                c = bit_rol(b, 30);
                b = a;
                a = t;
            }

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
            e = safe_add(e, olde);
        }
        return Array(a, b, c, d, e);
    }

    /**
     * Perform the appropriate triplet combination function for the current
     * iteration
     */

    private sha1_ft(t: number, b: any, c: any, d: any) {
        if (t < 20) {
            return (b & c) | ((~b) & d);
        }
        if (t < 40) {
            return b ^ c ^ d;
        }
        if (t < 60) {
            return (b & c) | (b & d) | (c & d);
        }
        return b ^ c ^ d;
    }

    /**
     * Determine the appropriate additive constant for the current iteration
     */

    private sha1_kt(t: number) {
        return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
            (t < 60) ? -1894007588 : -899497514;
    }
}