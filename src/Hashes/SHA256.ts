/**
* @class Hashes.SHA256
* @param {config}
*
* A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined in FIPS 180-2
* Version 2.2 Copyright Angel Marin, Paul Johnston 2000 - 2009.
* Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
* See http://pajhome.org.uk/crypt/md5 for details.
* Also http://anmar.eu.org/projects/jssha2/
*/
import {
    rstr2hex, rstr2b64, utf8Encode, safe_add,
    rstr2any, binb2rstr, rstr2binb
} from './Common'

export default class SHA256 {
    /**
     * Private properties configuration variables. You may need to tweak these to be compatible with
     * the server-side, but the defaults work in most cases.
     * @see this.setUpperCase() method
     * @see this.setPad() method
     */
    // private hexcase: boolean; // hexadecimal output case format. false - lowercase; true - uppercase
    private b64pad: string;// base-64 pad character. Defaults to '=' for strict RFC compliance
    private utf8: boolean; // enable/disable utf8 encoding
    private sha256_K: number[] = [
        1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
        1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
        264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
        113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
        1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
        430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
        1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998
    ];
    constructor(options?: any) {
        // super(); // 调用父类的 constructor(name)
        // this.options = options
        // this.hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false
        this.b64pad = (options && typeof options.pad === 'string') ? options.pad : '='
        this.utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true
    }

    /* privileged (public) methods */
    public hex(s:string) {
        return rstr2hex(this.rstr(s, this.utf8));
    };
    public b64(s:string) {
        return rstr2b64(this.rstr(s, this.utf8), this.b64pad);
    };
    public any(s:string, e: any) {
        return rstr2any(this.rstr(s, this.utf8), e);
    };
    public raw(s:string) {
        return this.rstr(s, this.utf8);
    };
    public hex_hmac(k: any, d: any) {
        return rstr2hex(this.rstr_hmac(k, d));
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
     * Enable/disable uppercase hexadecimal returned string
     * @param {boolean}
     * @return {Object} this
     * @public
     */
    // public setUpperCase(a:boolean) {
    //     if (typeof a === 'boolean') {
    //         this.hexcase = a;
    //     }
    //     return this;
    // };
    /**
     * @description Defines a base64 pad string
     * @param {string} Pad
     * @return {Object} this
     * @public
     */
    public setPad(a:string) {
        this.b64pad = a || this.b64pad;
        return this;
    };
    /**
     * Defines a base64 pad string
     * @param {boolean}
     * @return {Object} this
     * @public
     */
    public setUTF8(a:boolean) {
        if (typeof a === 'boolean') {
            this.utf8 = a;
        }
        return this;
    };

    // private methods

    /**
     * Calculate the SHA-512 of a raw string
     */

    private rstr(s: string, utf8: any) {
        s = (utf8) ? utf8Encode(s) : s;
        return binb2rstr(this.binb(rstr2binb(s), s.length * 8));
    }

    /**
     * Calculate the HMAC-sha256 of a key and some data (raw strings)
     */

    private rstr_hmac(key: any, data: any) {
        key = (this.utf8) ? utf8Encode(key) : key;
        data = (this.utf8) ? utf8Encode(data) : data;
        var hash, i = 0,
            bkey = rstr2binb(key),
            ipad = Array(16),
            opad = Array(16);

        if (bkey.length > 16) {
            bkey = this.binb(bkey, key.length * 8);
        }

        for (; i < 16; i += 1) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }

        hash = this.binb(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
        return binb2rstr(this.binb(opad.concat(hash), 512 + 256));
    }

    /*
     * Main sha256 function, with its support functions
     */

    private sha256_S(X:number, n:number) {
        return (X >>> n) | (X << (32 - n));
    }

    private sha256_R(X:number, n:number) {
        return (X >>> n);
    }

    private sha256_Ch(x:number, y:number, z:number) {
        return ((x & y) ^ ((~x) & z));
    }

    private sha256_Maj(x:number, y:number, z:number) {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    private sha256_Sigma0256(x:number) {
        return (this.sha256_S(x, 2) ^ this.sha256_S(x, 13) ^ this.sha256_S(x, 22));
    }

    private sha256_Sigma1256(x:number) {
        return (this.sha256_S(x, 6) ^ this.sha256_S(x, 11) ^ this.sha256_S(x, 25));
    }

    private sha256_Gamma0256(x:number) {
        return (this.sha256_S(x, 7) ^ this.sha256_S(x, 18) ^ this.sha256_R(x, 3));
    }

    private sha256_Gamma1256(x:number) {
        return (this.sha256_S(x, 17) ^ this.sha256_S(x, 19) ^ this.sha256_R(x, 10));
    }

    // private sha256_Sigma0512(x:number) {
    //     return (this.sha256_S(x, 28) ^ this.sha256_S(x, 34) ^ this.sha256_S(x, 39));
    // }

    // private sha256_Sigma1512(x:number) {
    //     return (this.sha256_S(x, 14) ^ this.sha256_S(x, 18) ^ this.sha256_S(x, 41));
    // }

    // private sha256_Gamma0512(x:number) {
    //     return (this.sha256_S(x, 1) ^ this.sha256_S(x, 8) ^ this.sha256_R(x, 7));
    // }

    // private sha256_Gamma1512(x:number) {
    //     return (this.sha256_S(x, 19) ^ this.sha256_S(x, 61) ^ this.sha256_R(x, 6));
    // }



    private binb(m: any, l:number) {
        var HASH = [1779033703, -1150833019, 1013904242, -1521486534,
            1359893119, -1694144372, 528734635, 1541459225
        ];
        var W = new Array(64);
        var a, b, c, d, e, f, g, h;
        var i, j, T1, T2;

        /* append padding */
        m[l >> 5] |= 0x80 << (24 - l % 32);
        m[((l + 64 >> 9) << 4) + 15] = l;

        for (i = 0; i < m.length; i += 16) {
            a = HASH[0];
            b = HASH[1];
            c = HASH[2];
            d = HASH[3];
            e = HASH[4];
            f = HASH[5];
            g = HASH[6];
            h = HASH[7];

            for (j = 0; j < 64; j += 1) {
                if (j < 16) {
                    W[j] = m[j + i];
                } else {
                    W[j] = safe_add(safe_add(safe_add(this.sha256_Gamma1256(W[j - 2]), W[j - 7]),
                        this.sha256_Gamma0256(W[j - 15])), W[j - 16]);
                }

                T1 = safe_add(safe_add(safe_add(safe_add(h, this.sha256_Sigma1256(e)), this.sha256_Ch(e, f, g)),
                    this.sha256_K[j]), W[j]);
                T2 = safe_add(this.sha256_Sigma0256(a), this.sha256_Maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = safe_add(d, T1);
                d = c;
                c = b;
                b = a;
                a = safe_add(T1, T2);
            }

            HASH[0] = safe_add(a, HASH[0]);
            HASH[1] = safe_add(b, HASH[1]);
            HASH[2] = safe_add(c, HASH[2]);
            HASH[3] = safe_add(d, HASH[3]);
            HASH[4] = safe_add(e, HASH[4]);
            HASH[5] = safe_add(f, HASH[5]);
            HASH[6] = safe_add(g, HASH[6]);
            HASH[7] = safe_add(h, HASH[7]);
        }
        return HASH;
    }

}