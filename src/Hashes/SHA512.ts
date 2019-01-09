/**
       * @class Hashes.SHA512
       * @param {config}
       *
       * A JavaScript implementation of the Secure Hash Algorithm, SHA-512, as defined in FIPS 180-2
       * Version 2.2 Copyright Anonymous Contributor, Paul Johnston 2000 - 2009.
       * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
       * See http://pajhome.org.uk/crypt/md5 for details.
       */

      import {
        rstr2hex, rstr2b64, utf8Encode,
        rstr2any, binb2rstr, rstr2binb
    } from './Common'

export default class SHA512 {

    // private hexcase: boolean; // hexadecimal output case format. false - lowercase; true - uppercase
    private b64pad: string;// base-64 pad character. Defaults to '=' for strict RFC compliance
    private utf8: boolean; // enable/disable utf8 encoding
    private sha512_k: int64[] = [
        new int64(0x428a2f98, -685199838), new int64(0x71374491, 0x23ef65cd),
        new int64(-1245643825, -330482897), new int64(-373957723, -2121671748),
        new int64(0x3956c25b, -213338824), new int64(0x59f111f1, -1241133031),
        new int64(-1841331548, -1357295717), new int64(-1424204075, -630357736),
        new int64(-670586216, -1560083902), new int64(0x12835b01, 0x45706fbe),
        new int64(0x243185be, 0x4ee4b28c), new int64(0x550c7dc3, -704662302),
        new int64(0x72be5d74, -226784913), new int64(-2132889090, 0x3b1696b1),
        new int64(-1680079193, 0x25c71235), new int64(-1046744716, -815192428),
        new int64(-459576895, -1628353838), new int64(-272742522, 0x384f25e3),
        new int64(0xfc19dc6, -1953704523), new int64(0x240ca1cc, 0x77ac9c65),
        new int64(0x2de92c6f, 0x592b0275), new int64(0x4a7484aa, 0x6ea6e483),
        new int64(0x5cb0a9dc, -1119749164), new int64(0x76f988da, -2096016459),
        new int64(-1740746414, -295247957), new int64(-1473132947, 0x2db43210),
        new int64(-1341970488, -1728372417), new int64(-1084653625, -1091629340),
        new int64(-958395405, 0x3da88fc2), new int64(-710438585, -1828018395),
        new int64(0x6ca6351, -536640913), new int64(0x14292967, 0xa0e6e70),
        new int64(0x27b70a85, 0x46d22ffc), new int64(0x2e1b2138, 0x5c26c926),
        new int64(0x4d2c6dfc, 0x5ac42aed), new int64(0x53380d13, -1651133473),
        new int64(0x650a7354, -1951439906), new int64(0x766a0abb, 0x3c77b2a8),
        new int64(-2117940946, 0x47edaee6), new int64(-1838011259, 0x1482353b),
        new int64(-1564481375, 0x4cf10364), new int64(-1474664885, -1136513023),
        new int64(-1035236496, -789014639), new int64(-949202525, 0x654be30),
        new int64(-778901479, -688958952), new int64(-694614492, 0x5565a910),
        new int64(-200395387, 0x5771202a), new int64(0x106aa070, 0x32bbd1b8),
        new int64(0x19a4c116, -1194143544), new int64(0x1e376c08, 0x5141ab53),
        new int64(0x2748774c, -544281703), new int64(0x34b0bcb5, -509917016),
        new int64(0x391c0cb3, -976659869), new int64(0x4ed8aa4a, -482243893),
        new int64(0x5b9cca4f, 0x7763e373), new int64(0x682e6ff3, -692930397),
        new int64(0x748f82ee, 0x5defb2fc), new int64(0x78a5636f, 0x43172f60),
        new int64(-2067236844, -1578062990), new int64(-1933114872, 0x1a6439ec),
        new int64(-1866530822, 0x23631e28), new int64(-1538233109, -561857047),
        new int64(-1090935817, -1295615723), new int64(-965641998, -479046869),
        new int64(-903397682, -366583396), new int64(-779700025, 0x21c0c207),
        new int64(-354779690, -840897762), new int64(-176337025, -294727304),
        new int64(0x6f067aa, 0x72176fba), new int64(0xa637dc5, -1563912026),
        new int64(0x113f9804, -1090974290), new int64(0x1b710b35, 0x131c471b),
        new int64(0x28db77f5, 0x23047d84), new int64(0x32caab7b, 0x40c72493),
        new int64(0x3c9ebe0a, 0x15c9bebc), new int64(0x431d67c4, -1676669620),
        new int64(0x4cc5d4be, -885112138), new int64(0x597f299c, -60457430),
        new int64(0x5fcb6fab, 0x3ad6faec), new int64(0x6c44198c, 0x4a475817)
    ]
    constructor(options?: any) {
        // super(); // 调用父类的 constructor(name)
        // this.options = options
        // this.hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false
        this.b64pad = (options && typeof options.pad === 'string') ? options.pad : '='
        this.utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true
    }
    /* privileged (public) methods */
    public hex (s:string) {
        return rstr2hex(this.rstr(s));
    };
    public b64 (s:string) {
        return rstr2b64(this.rstr(s), this.b64pad);
    };
    public any (s:string, e:any) {
        return rstr2any(this.rstr(s), e);
    };
    public raw (s:string) {
        return this.rstr(s);
    };
    public hex_hmac (k:any, d:any) {
        return rstr2hex(this.rstr_hmac(k, d));
    };
    public b64_hmac (k:any, d:any) {
        return rstr2b64(this.rstr_hmac(k, d), this.b64pad);
    };
    public any_hmac (k:any, d:any, e:any) {
        return rstr2any(this.rstr_hmac(k, d), e);
    };
    /**
     * Perform a simple self-test to see if the VM is working
     * @return {String} Hexadecimal hash sample
     * @public
     */
    public vm_test () {
        return this.hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
    };
    /**
     * @description Enable/disable uppercase hexadecimal returned string
     * @param {boolean}
     * @return {Object} this
     * @public
     */
    // public setUpperCase = function (a:boolean) {
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
    public setPad = function (a:string) {
        this.b64pad = a || this.b64pad;
        return this;
    };
    /**
     * @description Defines a base64 pad string
     * @param {boolean}
     * @return {Object} this
     * @public
     */
    public setUTF8 = function (a:boolean) {
        if (typeof a === 'boolean') {
            this.utf8 = a;
        }
        return this;
    };

    /* private methods */

    /**
     * Calculate the SHA-512 of a raw string
     */

    private rstr(s:string) {
        s = (this.utf8) ? utf8Encode(s) : s;
        return binb2rstr(this.binb(rstr2binb(s), s.length * 8));
    }
    /*
     * Calculate the HMAC-SHA-512 of a key and some data (raw strings)
     */

    private rstr_hmac(key: any, data: any) {
        key = (this.utf8) ? utf8Encode(key) : key;
        data = (this.utf8) ? utf8Encode(data) : data;

        var hash, i = 0,
            bkey = rstr2binb(key),
            ipad = Array(32),
            opad = Array(32);

        if (bkey.length > 32) {
            bkey = this.binb(bkey, key.length * 8);
        }

        for (; i < 32; i += 1) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }

        hash = this.binb(ipad.concat(rstr2binb(data)), 1024 + data.length * 8);
        return binb2rstr(this.binb(opad.concat(hash), 1024 + 512));
    }

    /**
     * Calculate the SHA-512 of an array of big-endian dwords, and a bit length
     */

    private binb(x: any, len: number) {
        var j, i, l,
            W = new Array(80),
            hash = new Array(16),
            //Initial hash values
            H = [
                new int64(0x6a09e667, -205731576),
                new int64(-1150833019, -2067093701),
                new int64(0x3c6ef372, -23791573),
                new int64(-1521486534, 0x5f1d36f1),
                new int64(0x510e527f, -1377402159),
                new int64(-1694144372, 0x2b3e6c1f),
                new int64(0x1f83d9ab, -79577749),
                new int64(0x5be0cd19, 0x137e2179)
            ],
            T1 = new int64(0, 0),
            T2 = new int64(0, 0),
            a = new int64(0, 0),
            b = new int64(0, 0),
            c = new int64(0, 0),
            d = new int64(0, 0),
            e = new int64(0, 0),
            f = new int64(0, 0),
            g = new int64(0, 0),
            h = new int64(0, 0),
            //Temporary variables not specified by the document
            s0 = new int64(0, 0),
            s1 = new int64(0, 0),
            Ch = new int64(0, 0),
            Maj = new int64(0, 0),
            r1 = new int64(0, 0),
            r2 = new int64(0, 0),
            r3 = new int64(0, 0);

        for (i = 0; i < 80; i += 1) {
            W[i] = new int64(0, 0);
        }

        // append padding to the source string. The format is described in the FIPS.
        x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
        x[((len + 128 >> 10) << 5) + 31] = len;
        l = x.length;
        for (i = 0; i < l; i += 32) { //32 dwords is the block size
            this.int64copy(a, H[0]);
            this.int64copy(b, H[1]);
            this.int64copy(c, H[2]);
            this.int64copy(d, H[3]);
            this.int64copy(e, H[4]);
            this.int64copy(f, H[5]);
            this.int64copy(g, H[6]);
            this.int64copy(h, H[7]);

            for (j = 0; j < 16; j += 1) {
                W[j].h = x[i + 2 * j];
                W[j].l = x[i + 2 * j + 1];
            }

            for (j = 16; j < 80; j += 1) {
                //sigma1
                this.int64rrot(r1, W[j - 2], 19);
                this.int64revrrot(r2, W[j - 2], 29);
                this.int64shr(r3, W[j - 2], 6);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;
                //sigma0
                this.int64rrot(r1, W[j - 15], 1);
                this.int64rrot(r2, W[j - 15], 8);
                this.int64shr(r3, W[j - 15], 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                this.int64add4(W[j], s1, W[j - 7], s0, W[j - 16]);
            }

            for (j = 0; j < 80; j += 1) {
                //Ch
                Ch.l = (e.l & f.l) ^ (~e.l & g.l);
                Ch.h = (e.h & f.h) ^ (~e.h & g.h);

                //Sigma1
                this.int64rrot(r1, e, 14);
                this.int64rrot(r2, e, 18);
                this.int64revrrot(r3, e, 9);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;

                //Sigma0
                this.int64rrot(r1, a, 28);
                this.int64revrrot(r2, a, 2);
                this.int64revrrot(r3, a, 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                //Maj
                Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
                Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

                this.int64add5(T1, h, s1, Ch, this.sha512_k[j], W[j]);
                this.int64add(T2, s0, Maj);

                this.int64copy(h, g);
                this.int64copy(g, f);
                this.int64copy(f, e);
                this.int64add(e, d, T1);
                this.int64copy(d, c);
                this.int64copy(c, b);
                this.int64copy(b, a);
                this.int64add(a, T1, T2);
            }
            this.int64add(H[0], H[0], a);
            this.int64add(H[1], H[1], b);
            this.int64add(H[2], H[2], c);
            this.int64add(H[3], H[3], d);
            this.int64add(H[4], H[4], e);
            this.int64add(H[5], H[5], f);
            this.int64add(H[6], H[6], g);
            this.int64add(H[7], H[7], h);
        }

        //represent the hash as an array of 32-bit dwords
        for (i = 0; i < 8; i += 1) {
            hash[2 * i] = H[i].h;
            hash[2 * i + 1] = H[i].l;
        }
        return hash;
    }

    //A constructor for 64-bit numbers

    // private int64(h: any, l: any) {
    //     this.h = h;
    //     this.l = l;
    //     //this.toString = int64toString;
    // }

    //Copies src into dst, assuming both are 64-bit numbers

    private int64copy(dst:any, src:any) {
        dst.h = src.h;
        dst.l = src.l;
    }

    //Right-rotates a 64-bit number by shift
    //Won't handle cases of shift>=32
    //The function revrrot() is for that

    private int64rrot(dst:any, x:any, shift:any) {
        dst.l = (x.l >>> shift) | (x.h << (32 - shift));
        dst.h = (x.h >>> shift) | (x.l << (32 - shift));
    }

    //Reverses the dwords of the source and then rotates right by shift.
    //This is equivalent to rotation by 32+shift

    private int64revrrot(dst:any, x:any, shift:any) {
        dst.l = (x.h >>> shift) | (x.l << (32 - shift));
        dst.h = (x.l >>> shift) | (x.h << (32 - shift));
    }

    //Bitwise-shifts right a 64-bit number by shift
    //Won't handle shift>=32, but it's never needed in SHA512

    private int64shr(dst:any, x:any, shift:any) {
        dst.l = (x.l >>> shift) | (x.h << (32 - shift));
        dst.h = (x.h >>> shift);
    }

    //Adds two 64-bit numbers
    //Like the original implementation, does not rely on 32-bit operations

    private int64add(dst:any, x:any, y:any) {
        var w0 = (x.l & 0xffff) + (y.l & 0xffff);
        var w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
        var w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
        var w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    }

    //Same, except with 4 addends. Works faster than adding them one by one.

    private int64add4(dst:any, a:any, b:any, c:any, d:any) {
        var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
        var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
        var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
        var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    }

    //Same, except with 5 addends

    private int64add5(dst:any, a:any, b:any, c:any, d:any, e:any) {
        var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff),
            w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16),
            w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16),
            w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
        dst.l = (w0 & 0xffff) | (w1 << 16);
        dst.h = (w2 & 0xffff) | (w3 << 16);
    }
}

class int64 {
    public h: number;
    public l: number;
    constructor(h: number, l: number){
        this.h = h;
        this.l = l;
    }
    //this.toString = int64toString;
}