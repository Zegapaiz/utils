/**
       * @class Hashes.RMD160
       * @constructor
       * @param {Object} [config]
       *
       * A JavaScript implementation of the RIPEMD-160 Algorithm
       * Version 2.2 Copyright Jeremy Lin, Paul Johnston 2000 - 2009.
       * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
       * See http://pajhome.org.uk/crypt/md5 for details.
       * Also http://www.ocf.berkeley.edu/~jjlin/jsotp/
       */

import {
  rstr2hex, rstr2b64, utf8Encode,
  rstr2any, safe_add, bit_rol, rstr2binl
} from './Common'

export default class RMD160 {
  // private hexcase: boolean; // hexadecimal output case format. false - lowercase; true - uppercase
  private b64pad: string;// base-64 pad character. Defaults to '=' for strict RFC compliance
  private utf8: boolean; // enable/disable utf8 encoding
  private rmd160_r1: number[] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
  ]
  private rmd160_r2: number[] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
  ]
  private rmd160_s1: number[] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
  ]
  private rmd160_s2 = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
  ]
  constructor(options?: any) {
    // super(); // 调用父类的 constructor(name)
    // this.options = options
    // this.hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false
    this.b64pad = (options && typeof options.pad === 'string') ? options.pad : '='
    this.utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true
  }


  /* privileged (public) methods */
  public hex(s: string) {
    return rstr2hex(this.rstr(s));
  };
  public b64(s: string) {
    return rstr2b64(this.rstr(s), this.b64pad);
  };
  public any(s: string, e: any) {
    return rstr2any(this.rstr(s), e);
  };
  public raw(s: string) {
    return this.rstr(s);
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
   * @description Enable/disable uppercase hexadecimal returned string
   * @param {boolean}
   * @return {Object} this
   * @public
   */
  // public setUpperCase(a: boolean) {
  //   if (typeof a === 'boolean') {
  //     this.hexcase = a;
  //   }
  //   return this;
  // };
  /**
   * @description Defines a base64 pad string
   * @param {string} Pad
   * @return {Object} this
   * @public
   */
  public setPad(a: string) {
    if (typeof a !== 'undefined') {
      this.b64pad = a;
    }
    return this;
  };
  /**
   * @description Defines a base64 pad string
   * @param {boolean}
   * @return {Object} this
   * @public
   */
  public setUTF8(a: boolean) {
    if (typeof a === 'boolean') {
      this.utf8 = a;
    }
    return this;
  };

  /* private methods */

  /**
   * Calculate the rmd160 of a raw string
   */

  private rstr(s: string) {
    s = (this.utf8) ? utf8Encode(s) : s;
    return this.binl2rstr(this.binl(rstr2binl(s), s.length * 8));
  }

  /**
   * Calculate the HMAC-rmd160 of a key and some data (raw strings)
   */

  private rstr_hmac(key: any, data: any) {
    key = (this.utf8) ? utf8Encode(key) : key;
    data = (this.utf8) ? utf8Encode(data) : data;
    var i, hash,
      bkey = rstr2binl(key),
      ipad = Array(16),
      opad = Array(16);

    if (bkey.length > 16) {
      bkey = this.binl(bkey, key.length * 8);
    }

    for (i = 0; i < 16; i += 1) {
      ipad[i] = bkey[i] ^ 0x36363636;
      opad[i] = bkey[i] ^ 0x5C5C5C5C;
    }
    hash = this.binl(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
    return this.binl2rstr(this.binl(opad.concat(hash), 512 + 160));
  }

  /**
   * Convert an array of little-endian words to a string
   */

  private binl2rstr(input: any) {
    var i, output = '',
      l = input.length * 32;
    for (i = 0; i < l; i += 8) {
      output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
    }
    return output;
  }

  /**
   * Calculate the RIPE-MD160 of an array of little-endian words, and a bit length.
   */

  private binl(x: any, len: number) {
    var T, j, i, l,
      h0 = 0x67452301,
      h1 = 0xefcdab89,
      h2 = 0x98badcfe,
      h3 = 0x10325476,
      h4 = 0xc3d2e1f0,
      A1, B1, C1, D1, E1,
      A2, B2, C2, D2, E2;

    /* append padding */
    x[len >> 5] |= 0x80 << (len % 32);
    x[(((len + 64) >>> 9) << 4) + 14] = len;
    l = x.length;

    for (i = 0; i < l; i += 16) {
      A1 = A2 = h0;
      B1 = B2 = h1;
      C1 = C2 = h2;
      D1 = D2 = h3;
      E1 = E2 = h4;
      for (j = 0; j <= 79; j += 1) {
        T = safe_add(A1, this.rmd160_f(j, B1, C1, D1));
        T = safe_add(T, x[i + this.rmd160_r1[j]]);
        T = safe_add(T, this.rmd160_K1(j));
        T = safe_add(bit_rol(T, this.rmd160_s1[j]), E1);
        A1 = E1;
        E1 = D1;
        D1 = bit_rol(C1, 10);
        C1 = B1;
        B1 = T;
        T = safe_add(A2, this.rmd160_f(79 - j, B2, C2, D2));
        T = safe_add(T, x[i + this.rmd160_r2[j]]);
        T = safe_add(T, this.rmd160_K2(j));
        T = safe_add(bit_rol(T, this.rmd160_s2[j]), E2);
        A2 = E2;
        E2 = D2;
        D2 = bit_rol(C2, 10);
        C2 = B2;
        B2 = T;
      }

      T = safe_add(h1, safe_add(C1, D2));
      h1 = safe_add(h2, safe_add(D1, E2));
      h2 = safe_add(h3, safe_add(E1, A2));
      h3 = safe_add(h4, safe_add(A1, B2));
      h4 = safe_add(h0, safe_add(B1, C2));
      h0 = T;
    }
    return [h0, h1, h2, h3, h4];
  }

  // specific algorithm methods

  private rmd160_f(j: number, x: number, y: number, z: number) {
    return (0 <= j && j <= 15) ? (x ^ y ^ z) :
      (16 <= j && j <= 31) ? (x & y) | (~x & z) :
        (32 <= j && j <= 47) ? (x | ~y) ^ z :
          (48 <= j && j <= 63) ? (x & z) | (y & ~z) :
            (64 <= j && j <= 79) ? x ^ (y | ~z) :
              'rmd160_f: j out of range';
  }

  private rmd160_K1(j: number) {
    return (0 <= j && j <= 15) ? 0x00000000 :
      (16 <= j && j <= 31) ? 0x5a827999 :
        (32 <= j && j <= 47) ? 0x6ed9eba1 :
          (48 <= j && j <= 63) ? 0x8f1bbcdc :
            (64 <= j && j <= 79) ? 0xa953fd4e :
              'rmd160_K1: j out of range';
  }

  private rmd160_K2(j: number) {
    return (0 <= j && j <= 15) ? 0x50a28be6 :
      (16 <= j && j <= 31) ? 0x5c4dd124 :
        (32 <= j && j <= 47) ? 0x6d703ef3 :
          (48 <= j && j <= 63) ? 0x7a6d76e9 :
            (64 <= j && j <= 79) ? 0x00000000 :
              'rmd160_K2: j out of range';
  }
}