/**
 * Nudge
 * 
 * - ECDH key exchange
 * - Double ratchet algorithm for forward secrecy
 * - Envelope encryption for secure messaging
 * - Session management with state persistence
 * 
 * @author thejordanprice
 * @version 2.0.0
 */

'use strict';

/**
 * Utility functions for encoding/decoding and cryptographic operations
 */
class CryptoUtils {
  static textToBytes(text) {
    return new TextEncoder().encode(text);
  }

  static bytesToText(bytes) {
    return new TextDecoder().decode(bytes);
  }

  static bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] & 0xff);
    }
    return btoa(binary);
  }

  static base64ToBytes(base64) {
    const binary = atob(base64);
    return new Uint8Array([...binary].map(char => char.charCodeAt(0)));
  }

  static combine(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    
    return result;
  }

  static randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  static deepClone(obj) {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }
    
    if (obj instanceof Date) {
      return new Date(obj.getTime());
    }
    
    if (obj instanceof Uint8Array) {
      return new Uint8Array(obj);
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => CryptoUtils.deepClone(item));
    }
    
    const cloned = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        cloned[key] = CryptoUtils.deepClone(obj[key]);
      }
    }
    
    return cloned;
  }

  static serializeHeader(header) {
    if (!header || typeof header !== 'object') return '';
    const sorted = {};
    Object.keys(header).sort().forEach(k => { sorted[k] = header[k]; });
    return JSON.stringify(sorted);
  }
}

class ECDHKeyPair {
  static async generate() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const privateKeyBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    console.log('[DEBUG] ECDHKeyPair.generate: publicKeyBytes[0-7]:', Array.from(publicKeyBytes.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('[DEBUG] ECDHKeyPair.generate: privateKeyBytes[0-7]:', Array.from(privateKeyBytes.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      pub: publicKeyBytes,
      key: privateKeyBytes
    };
  }

  static async importPublicKey(publicKeyBytes) {
    if (publicKeyBytes instanceof Uint8Array) {
      publicKeyBytes = publicKeyBytes.buffer;
    }
    console.log('[DEBUG] ECDHKeyPair.importPublicKey: bytes[0-7]:', Array.from(new Uint8Array(publicKeyBytes).slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    return await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      []
    );
  }

  static async importPrivateKey(privateKeyBytes) {
    if (privateKeyBytes instanceof Uint8Array) {
      privateKeyBytes = privateKeyBytes.buffer;
    }
    console.log('[DEBUG] ECDHKeyPair.importPrivateKey: bytes[0-7]:', Array.from(new Uint8Array(privateKeyBytes).slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    return await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBytes,
      {
        name: 'ECDH',
        namedCurve: 'P-256'
      },
      true,
      ['deriveKey', 'deriveBits']
    );
  }

  static async deriveSecret(privateKey, publicKey) {
    return new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: publicKey
        },
        privateKey,
        256
      )
    );
  }

  static async derive(privateKey, publicKey) {
    return await ECDHKeyPair.deriveSecret(privateKey, publicKey);
  }

  static async deriveFromBytes(privateKeyBytes, publicKeyBytes) {
    const privateKey = await ECDHKeyPair.importPrivateKey(privateKeyBytes);
    const publicKey = await ECDHKeyPair.importPublicKey(publicKeyBytes);
    return await ECDHKeyPair.derive(privateKey, publicKey);
  }
}

class KDF {
  static async derive(inputKeyMaterial, salt, info, length) {
    const key = await crypto.subtle.importKey(
      'raw',
      inputKeyMaterial,
      'HKDF',
      false,
      ['deriveBits']
    );

    return new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'HKDF',
          salt: salt,
          info: info,
          hash: 'SHA-256'
        },
        key,
        length
      )
    );
  }

  static async hmac(key, data) {
    if (typeof key === 'string') {
      key = CryptoUtils.textToBytes(key);
    }
    if (!(key instanceof Uint8Array || key instanceof ArrayBuffer)) {
      throw new TypeError('KDF.hmac: key must be Uint8Array or ArrayBuffer');
    }
    if (key instanceof Uint8Array) {
      key = key.buffer;
    }
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      {
        name: 'HMAC',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
    return new Uint8Array(signature);
  }
}

class AEAD {
  static async encrypt(plaintext, key, associatedData) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error(`AEAD.encrypt: Invalid key length ${key ? key.length : 'undefined'}, expected 32`);
    }
    if (!(associatedData instanceof Uint8Array)) {
      throw new Error('AEAD.encrypt: associatedData must be Uint8Array');
    }
    
    console.log(`AEAD.encrypt: key length=${key.length}, AD length=${associatedData.length}, plaintext length=${plaintext.length}`);
    console.log(`AEAD.encrypt: key[0-3]=${Array.from(key.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}, AD[0-3]=${Array.from(associatedData.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const nullBytes = Array.from(associatedData).filter(b => b === 0).length;
    const nonPrintable = Array.from(associatedData).filter(b => b < 32 || b > 126).length;
    if (nullBytes > 0 || nonPrintable > 0) {
      console.log(`AEAD.encrypt: WARNING - AD contains ${nullBytes} null bytes and ${nonPrintable} non-printable characters`);
    }
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['encrypt']
    );

    const iv = CryptoUtils.randomBytes(12);
    const encodedPlaintext = CryptoUtils.textToBytes(plaintext);
    
    console.log(`AEAD.encrypt: FULL AD: ${Array.from(associatedData).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.encrypt: FULL IV: ${Array.from(iv).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.encrypt: FULL KEY: ${Array.from(key).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);

    console.log(`AEAD.encrypt: IV length=${iv.length}, encoded plaintext length=${encodedPlaintext.length}`);
    console.log(`AEAD.encrypt: IV[0-3]=${Array.from(iv.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    let adBuffer;
    if (associatedData instanceof Uint8Array) {
      const adCopy = new Uint8Array(associatedData);
      adBuffer = adCopy.buffer;
      console.log(`AEAD.encrypt: Using Uint8Array copy: original length=${associatedData.length}, copy length=${adCopy.length}, buffer length=${adBuffer.byteLength}`);
    } else {
      adBuffer = associatedData;
    }
    
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: adBuffer
      },
      cryptoKey,
      encodedPlaintext
    );

    const result = CryptoUtils.combine(iv, new Uint8Array(ciphertext));
    console.log(`AEAD.encrypt: result[0-3]=${Array.from(result.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    return result;
  }

  static async decrypt(ciphertext, key, associatedData) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new Error(`AEAD.decrypt: Invalid key length ${key ? key.length : 'undefined'}, expected 32`);
    }
    if (!(associatedData instanceof Uint8Array)) {
      throw new Error('AEAD.decrypt: associatedData must be Uint8Array');
    }
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 12) {
      throw new Error(`AEAD.decrypt: Invalid ciphertext length ${ciphertext ? ciphertext.length : 'undefined'}, expected at least 12 bytes`);
    }
    
    console.log(`AEAD.decrypt: key length=${key.length}, AD length=${associatedData.length}, ciphertext length=${ciphertext.length}`);
    console.log(`AEAD.decrypt: key[0-3]=${Array.from(key.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}, AD[0-3]=${Array.from(associatedData.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.decrypt: WARNING - AD contains ${Array.from(associatedData).filter(b => b === 0).length} null bytes and ${Array.from(associatedData).filter(b => b < 32 || b > 126).length} non-printable characters`);
    console.log(`AEAD.decrypt: FULL AD: ${Array.from(associatedData).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.decrypt: FULL IV: ${Array.from(ciphertext.slice(0,12)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.decrypt: FULL KEY: ${Array.from(key).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.decrypt: IV length=${ciphertext.slice(0,12).length}, encrypted data length=${ciphertext.slice(12).length}`);
    console.log(`AEAD.decrypt: IV[0-3]=${Array.from(ciphertext.slice(0,12).slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.decrypt: encryptedData[0-3]=${Array.from(ciphertext.slice(12).slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`AEAD.decrypt: ciphertext[0-3]=${Array.from(ciphertext.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    console.log(`AEAD.decrypt: CRITICAL DEBUG - Before AES-GCM:`);
    console.log(`  - key type=${Object.prototype.toString.call(key)}, length=${key.length}, [0-3]=${Array.from(key.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - iv type=${Object.prototype.toString.call(ciphertext.slice(0,12))}, length=${ciphertext.slice(0,12).length}, [0-3]=${Array.from(ciphertext.slice(0,12).slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - encryptedData type=${Object.prototype.toString.call(ciphertext.slice(12))}, length=${ciphertext.slice(12).length}, [0-3]=${Array.from(ciphertext.slice(12).slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - associatedData type=${Object.prototype.toString.call(associatedData)}, length=${associatedData.length}, [0-3]=${Array.from(associatedData.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      ['decrypt']
    );
    
    try {
      let adBuffer;
      if (associatedData instanceof Uint8Array) {
        const adCopy = new Uint8Array(associatedData);
        adBuffer = adCopy.buffer;
        console.log(`AEAD.decrypt: Using Uint8Array copy: original length=${associatedData.length}, copy length=${adCopy.length}, buffer length=${adBuffer.byteLength}`);
      } else {
        adBuffer = associatedData;
      }
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ciphertext.slice(0, 12),
          additionalData: adBuffer
        },
        cryptoKey,
        ciphertext.slice(12)
      );

      return CryptoUtils.bytesToText(new Uint8Array(decrypted));
    } catch (error) {
      console.error(`AEAD.decrypt: AES-GCM decryption failed:`, error);
      console.error(`AEAD.decrypt: Key bytes:`, Array.from(key).map(b => b.toString(16).padStart(2,'0')).join(' '));
      console.error(`AEAD.decrypt: AD bytes:`, Array.from(associatedData).map(b => b.toString(16).padStart(2,'0')).join(' '));
      console.error(`AEAD.decrypt: IV bytes:`, Array.from(ciphertext.slice(0,12)).map(b => b.toString(16).padStart(2,'0')).join(' '));
      throw error;
    }
  }
}

class SessionManager {
  static async createInitRatchet(session) {
    const epk = session.init.epk;
    const epkPrivate = session.init.epkPrivate;
    const state = {
      DHs: { pub: epk, key: epkPrivate },
      DHr: session.init.opk,
      RK: session.sk,
      CKs: null,
      CKr: null,
      Ns: 0,
      Nr: 0,
      PN: 0,
      MKSKIPPED: {}
    };
    // Debug: Print ECDH inputs (initiator)
    console.log('[DEBUG] createInitRatchet (initiator):');
    console.log('  DHs.key (ephemeral private) [0-7]:', Array.from(state.DHs.key.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  DHr (opk public) [0-7]:', Array.from(state.DHr.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    // Derive DH shared secret for sending chain
    const dh = await ECDHKeyPair.deriveFromBytes(state.DHs.key, state.DHr);
    console.log('  DH shared secret [0-7]:', Array.from(dh.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  RK (session.sk) [0-7]:', Array.from(session.sk.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    const [rk, ck] = await SessionManager.rootKDF(session.sk, dh);
    console.log('  rootKDF output RK [0-7]:', Array.from(rk.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  rootKDF output CK [0-7]:', Array.from(ck.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    state.RK = rk;
    state.CKs = ck instanceof Uint8Array ? ck : new Uint8Array(ck);
    state.CKr = null;
    console.log('[DEBUG] createInitRatchet (initiator): CKs:', Array.from(state.CKs).map(b => b.toString(16).padStart(2, '0')).join(' '));
    return state;
  }

  static async openInitRatchet(session, opk) {
    if (session.sk && opk && opk.key && opk.pub && session.init && session.init.epk) {
      // Debug: Print ECDH inputs (responder)
      console.log('[DEBUG] openInitRatchet (responder):');
      console.log('  opk.key (opk private) [0-7]:', Array.from(opk.key.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
      console.log('  session.init.epk (ephemeral public) [0-7]:', Array.from(session.init.epk.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
      const dh = await ECDHKeyPair.deriveFromBytes(opk.key, session.init.epk);
      console.log('  DH shared secret [0-7]:', Array.from(dh.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
      console.log('  RK (session.sk) [0-7]:', Array.from(session.sk.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
      const [rk, ck] = await SessionManager.rootKDF(session.sk, dh);
      console.log('  rootKDF output RK [0-7]:', Array.from(rk.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
      console.log('  rootKDF output CK [0-7]:', Array.from(ck.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
      session.sk = rk;
      const state = {
        DHs: opk,
        DHr: session.init ? session.init.epk : opk.pub,
        RK: session.sk,
        CKs: null,
        CKr: ck instanceof Uint8Array ? ck : new Uint8Array(ck),
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED: {}
      };
      console.log('[DEBUG] openInitRatchet (responder): CKr:', Array.from(state.CKr).map(b => b.toString(16).padStart(2, '0')).join(' '));
      return state;
    } else {
      throw new Error('openInitRatchet: Missing required data for CKr initialization');
    }
  }

  static async rootKDF(rk, dh) {
    const ratchet = await KDF.derive(
      dh,
      rk,
      CryptoUtils.textToBytes('ROOT'),
      512
    );
    
    const RK = ratchet.slice(0, 32);
    const CK = ratchet.slice(32);
    
    return [RK, CK];
  }

  static async chainKDF(ck) {
    if (!(ck instanceof Uint8Array || ck instanceof ArrayBuffer)) {
      console.error('SessionManager.chainKDF: Invalid chain key:', ck);
      throw new TypeError('SessionManager.chainKDF: chain key must be Uint8Array or ArrayBuffer');
    }
    console.log(`chainKDF: input ck[0-3]=${Array.from(ck.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    const mk = await KDF.hmac(ck, new Uint8Array([0x01]));
    const CK = await KDF.hmac(ck, new Uint8Array([0x02]));
    console.log(`chainKDF: output mk[0-3]=${Array.from(mk.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}, CK[0-3]=${Array.from(CK.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    return [CK, mk];
  }

  static async trySkippedMessageKeys(state, header, ciphertext, aead) {
    if (!state.MKSKIPPED[header.dh] || !state.MKSKIPPED[header.dh][header.n]) {
      return null;
    }

    const mk = state.MKSKIPPED[header.dh][header.n];
    const key = await KDF.derive(
      CryptoUtils.combine(mk, CryptoUtils.textToBytes(CryptoUtils.serializeHeader(header))),
      new Uint8Array(32),
      CryptoUtils.textToBytes('ENCRYPT'),
      256
    );

    try {
      const plaintext = await AEAD.decrypt(ciphertext, key, aead);
      delete state.MKSKIPPED[header.dh][header.n];
      return { header, plaintext: JSON.parse(plaintext) };
    } catch (error) {
      return null;
    }
  }

  static async skipMessageKeys(state, until, maxSkip) {
    if (state.Nr + maxSkip < until) {
      throw new Error('Too many skipped messages!');
    }

    if (state.CKr) {
      while (state.Nr < until) {
        const [ck, mk] = await SessionManager.chainKDF(state.CKr);
        if (!state.MKSKIPPED[state.DHr]) {
          state.MKSKIPPED[state.DHr] = {};
        }
        state.MKSKIPPED[state.DHr][state.Nr] = mk;
        state.CKr = ck;
        state.Nr += 1;
      }
    }
  }

  static async DHRatchet(state, header) {
    console.log(`DHRatchet: Starting DH ratchet step`);
    console.log(`DHRatchet: state.DHs.key length=${state.DHs.key ? state.DHs.key.length : 0}, header.dh length=${header.dh ? header.dh.length : 0}`);
    if (state.DHs && state.DHs.pub) {
      console.log(`DHRatchet: state.DHs.pub (hex): ${Array.from(state.DHs.pub).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    }
    if (state.DHs && state.DHs.key) {
      console.log(`DHRatchet: state.DHs.key (hex): ${Array.from(new Uint8Array(state.DHs.key)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    }
    if (header.dh) {
      console.log(`DHRatchet: header.dh (hex): ${Array.from(header.dh).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    }
    
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.DHr = header.dh;
    if (state.DHr && typeof state.DHr === 'string') {
      state.DHr = CryptoUtils.base64ToBytes(state.DHr);
      console.log('DHRatchet: Converted state.DHr from base64 to Uint8Array');
    }
    console.log(`DHRatchet: state.DHr type=${Object.prototype.toString.call(state.DHr)}, length=${state.DHr ? state.DHr.length : 'null'}`);
    
    console.log(`DHRatchet: BEFORE DH1: state.DHs.key[0-3]=${Array.from(state.DHs.key.slice(0,4)).map(b=>b.toString(16)).join(' ')}, header.dh[0-3]=${Array.from(header.dh.slice(0,4)).map(b=>b.toString(16)).join(' ')}`);
    
    const dh1 = await ECDHKeyPair.deriveFromBytes(state.DHs.key, state.DHr);
    console.log(`DHRatchet: dh1 (shared secret) (hex): ${Array.from(dh1).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    const [rk1, ckr] = await SessionManager.rootKDF(state.RK, dh1);
    console.log(`DHRatchet: rk1 (hex): ${Array.from(rk1).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`DHRatchet: ckr (hex): ${Array.from(ckr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    state.RK = rk1;
    state.CKr = ckr;
    
    console.log(`DHRatchet: Generating new DH key pair for second ECDH operation`);
    state.DHs = await ECDHKeyPair.generate();
    console.log(`DHRatchet: New DHs.pub (hex): ${Array.from(state.DHs.pub).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`DHRatchet: New DHs.key (hex): ${Array.from(new Uint8Array(state.DHs.key)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const dh2 = await ECDHKeyPair.deriveFromBytes(state.DHs.key, state.DHr);
    console.log(`DHRatchet: dh2 (shared secret) (hex): ${Array.from(dh2).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    const [rk2, cks2] = await SessionManager.rootKDF(state.RK, dh2);
    console.log(`DHRatchet: rk2 (hex): ${Array.from(rk2).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`DHRatchet: cks2 (hex): ${Array.from(cks2).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    state.RK = rk2;
    state.CKs = cks2 instanceof Uint8Array ? cks2 : new Uint8Array(cks2);
    
    delete state.shouldDHratchet;
    return true;
  }

  static async ratchetEncrypt(state, message, ad, init) {
    console.log(`ratchetEncrypt: STATE BEFORE: Ns=${state.Ns}, Nr=${state.Nr}, CKs=${state.CKs ? Array.from(state.CKs).map(b=>b.toString(16)).join(' ') : 'null'}, CKr=${state.CKr ? Array.from(state.CKr).map(b=>b.toString(16)).join(' ') : 'null'}, DHs.pub=${state.DHs && state.DHs.pub ? CryptoUtils.bytesToBase64(state.DHs.pub) : 'null'}, DHr=${state.DHr ? CryptoUtils.bytesToBase64(state.DHr) : 'null'}`);
    
    if (!state.CKs) {
      console.log(`ratchetEncrypt: CKs is not initialized, generating new DH key pair for first message`);
      state.DHs = await ECDHKeyPair.generate();
      state.expectNextDH = true;
      console.log(`ratchetEncrypt: New DHs.pub (base64): ${CryptoUtils.bytesToBase64(state.DHs.pub)}`);
      console.log(`ratchetEncrypt: New DHs.pub (hex): ${Array.from(state.DHs.pub).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetEncrypt: New DHs.key (hex): ${Array.from(new Uint8Array(state.DHs.key)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      if (state.DHr) {
        console.log(`ratchetEncrypt: DHr (hex): ${Array.from(state.DHr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
      
      const dh2 = await ECDHKeyPair.deriveFromBytes(state.DHs.key, state.DHr);
      console.log(`ratchetEncrypt: dh2 (shared secret) (hex): ${Array.from(dh2).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      const [rk2, cks2] = await SessionManager.rootKDF(state.RK, dh2);
      console.log(`ratchetEncrypt: rk2 (hex): ${Array.from(rk2).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetEncrypt: cks2 (hex): ${Array.from(cks2).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      state.RK = rk2;
      state.CKs = cks2 instanceof Uint8Array ? cks2 : new Uint8Array(cks2);
      console.log(`ratchetEncrypt: After DH generation - state.DHs.pub (base64): ${CryptoUtils.bytesToBase64(state.DHs.pub)}`);
    }
    
    if (!state.CKs || !(state.CKs instanceof Uint8Array) || state.CKs.length !== 32) {
      throw new Error("ratchetEncrypt: CKs (sending chain key) is not initialized or invalid!");
    }
    
    console.log(`ratchetEncrypt: ad type=${Object.prototype.toString.call(ad)}, length=${ad ? ad.length : 0}, [0-3]=${ad ? Array.from(ad.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ') : ''}`);
    
    if (!state.DHs || !state.DHs.key) {
      console.error('ratchetEncrypt: state.DHs.key is missing!');
    } else if (!(state.DHs.key instanceof Uint8Array || state.DHs.key instanceof ArrayBuffer)) {
      console.error('ratchetEncrypt: state.DHs.key is not a Uint8Array or ArrayBuffer:', state.DHs.key);
    }
    
    try {
      const dhsPubB64 = state.DHs && state.DHs.pub ? CryptoUtils.bytesToBase64(state.DHs.pub) : 'null';
      const dhsKeyBytes = state.DHs && state.DHs.key ? Array.from(new Uint8Array(state.DHs.key).slice(0,4)).map(b=>b.toString(16)).join(' ') : 'null';
      const dhrB64 = state.DHr ? CryptoUtils.bytesToBase64(state.DHr) : 'null';
      console.log(`ratchetEncrypt: DHs.pub=${dhsPubB64}, DHs.key[0-3]=${dhsKeyBytes}, DHr=${dhrB64}`);
      if (state.DHs && state.DHs.pub) {
        console.log(`ratchetEncrypt: DHs.pub (hex): ${Array.from(state.DHs.pub).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
      if (state.DHs && state.DHs.key) {
        console.log(`ratchetEncrypt: DHs.key (hex): ${Array.from(new Uint8Array(state.DHs.key)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
      if (state.DHr) {
        console.log(`ratchetEncrypt: DHr (hex): ${Array.from(state.DHr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
    } catch (e) {
      console.error('ratchetEncrypt: error logging DH keys', e);
    }
    
    console.log(`ratchetEncrypt: CKs type=${typeof state.CKs}, length=${state.CKs ? state.CKs.length : 0}`);
    if (state.CKs) console.log(`ratchetEncrypt: CKs (hex): ${Array.from(state.CKs).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    console.log(`ratchetEncrypt: CKs before chainKDF: ${Array.from(state.CKs).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const [cks, mk] = await SessionManager.chainKDF(state.CKs);
    console.log(`ratchetEncrypt: mk (hex): ${Array.from(mk).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`ratchetEncrypt: cks (hex): ${Array.from(cks).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    
    console.log(`ratchetEncrypt: CHAIN KEY ADVANCEMENT:`);
    console.log(`  - CKs before chainKDF: ${Array.from(state.CKs).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - mk derived from CKs: ${Array.from(mk).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - cks (new CKs): ${Array.from(cks).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - Order: CKs -> mk -> cks (correct)`);
    
    const header = {
      dh: CryptoUtils.bytesToBase64(state.DHs.pub),
      pn: state.PN,
      n: state.Ns
    };
    
    console.log(`ratchetEncrypt: header.dh (base64): ${header.dh}`);
    console.log(`ratchetEncrypt: header.dh (hex): ${Array.from(state.DHs.pub).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    const headerString = CryptoUtils.serializeHeader(header);
    const headerBytes = CryptoUtils.textToBytes(headerString);
    
    console.log(`ratchetEncrypt: header string: ${headerString}`);
    console.log(`ratchetEncrypt: headerBytes (hex): ${Array.from(headerBytes).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`ratchetEncrypt: AD (hex): ${Array.from(ad).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const combinedBytes = CryptoUtils.combine(mk, headerBytes);
    console.log(`ratchetEncrypt: KDF input (mk+headerBytes) (hex): ${Array.from(combinedBytes).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const headerForKDF = JSON.parse(JSON.stringify(header));
    const key = await KDF.derive(
      combinedBytes,
      new Uint8Array(32),
      CryptoUtils.textToBytes('ENCRYPT'),
      256
    );
    
    if (CryptoUtils.serializeHeader(header) !== headerString) {
      console.error('ratchetEncrypt: header mutated after KDF!');
    }

    console.log(`ratchetEncrypt: PLAINTEXT BEFORE ENCRYPT:`, JSON.stringify(message));
    console.log(`ratchetEncrypt: About to call AEAD.encrypt with:`);
    console.log(`  - key length: ${key.length}, key[0-3]: ${Array.from(key.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - ad length: ${ad.length}, ad[0-3]: ${Array.from(ad.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const ciphertext = await AEAD.encrypt(
      JSON.stringify(message),
      key,
      ad
    );
    
    const ciphertextBase64 = CryptoUtils.bytesToBase64(ciphertext);
    console.log(`ratchetEncrypt: CIPHERTEXT AFTER ENCRYPT (base64):`, ciphertextBase64);
    
    if (header) header._debugCiphertextB64 = ciphertextBase64;
    
    if (CryptoUtils.serializeHeader(header) !== headerString) {
      console.error('ratchetEncrypt: header mutated after AEAD!');
    }

    console.log(`ratchetEncrypt: ENCRYPTION VALUES:`);
    console.log(`  - mk (message key): ${Array.from(mk).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - header string: ${headerString}`);
    console.log(`  - header bytes: ${Array.from(headerBytes).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - AD: ${Array.from(ad).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - key (derived from mk+header): ${Array.from(key).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - ciphertext: ${Array.from(ciphertext).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);

    console.log(`ratchetEncrypt: BEFORE ADVANCE mk=${Array.from(mk).map(b=>b.toString(16).padStart(2,'0')).join(' ')}, cks=${Array.from(state.CKs).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    
    state.Ns += 1;
    state.CKs = cks;
    
    console.log(`ratchetEncrypt: AFTER ADVANCE cks=${Array.from(state.CKs).map(b=>b.toString(16).padStart(2,'0')).join(' ')}, Ns=${state.Ns}`);
    console.log(`ratchetEncrypt: STATE AFTER: Ns=${state.Ns}, Nr=${state.Nr}, CKs=${state.CKs ? Array.from(state.CKs).map(b=>b.toString(16)).join(' ') : 'null'}, CKr=${state.CKr ? Array.from(state.CKr).map(b=>b.toString(16)).join(' ') : 'null'}, DHs.pub=${state.DHs && state.DHs.pub ? CryptoUtils.bytesToBase64(state.DHs.pub) : 'null'}, DHr=${state.DHr ? CryptoUtils.bytesToBase64(state.DHr) : 'null'}`);

    const encrypted = { header, ciphertext };
    if (init) {
      encrypted.init = CryptoUtils.deepClone(init);
    }

    console.log(`ratchetEncrypt: Returning encrypted message with header: ${JSON.stringify(encrypted.header)}`);
    console.log(`ratchetEncrypt: header.dh in return: ${encrypted.header.dh}`);

    return encrypted;
  }

  static async ratchetDecrypt(state, msgPayload = {}, ad, maxSkip = 10) {
    console.log(`ratchetDecrypt: STATE BEFORE: Ns=${state.Ns}, Nr=${state.Nr}, CKs=${state.CKs ? Array.from(state.CKs).map(b=>b.toString(16)).join(' ') : 'null'}, CKr=${state.CKr ? Array.from(state.CKr).map(b=>b.toString(16)).join(' ') : 'null'}, DHs.pub=${state.DHs && state.DHs.pub ? CryptoUtils.bytesToBase64(state.DHs.pub) : 'null'}, DHr=${state.DHr ? CryptoUtils.bytesToBase64(state.DHr) : 'null'}`);
    
    console.log(`ratchetDecrypt: ad type=${Object.prototype.toString.call(ad)}, length=${ad ? ad.length : 0}, [0-3]=${ad ? Array.from(ad.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ') : ''}`);
    console.log(`ratchetDecrypt: msgPayload type=${typeof msgPayload}, keys=${Object.keys(msgPayload)}`);
    console.log(`ratchetDecrypt: msgPayload.header: ${JSON.stringify(msgPayload.header)}`);
    
    const { ciphertext } = msgPayload;
    const header = CryptoUtils.deepClone(msgPayload.header);
    const originalHeader = CryptoUtils.deepClone(header);
    const originalHeaderString = CryptoUtils.serializeHeader(originalHeader);
    
    if (header && header.dh) {
      if (typeof header.dh === 'string') {
        console.log(`ratchetDecrypt: received header.dh (base64): ${header.dh}`);
        try {
          const dhBytes = CryptoUtils.base64ToBytes(header.dh);
          console.log(`ratchetDecrypt: received header.dh (hex): ${Array.from(dhBytes).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
        } catch (e) {
          console.error('ratchetDecrypt: error decoding header.dh base64:', e);
        }
      } else if (header.dh instanceof Uint8Array) {
        console.log(`ratchetDecrypt: received header.dh (hex): ${Array.from(header.dh).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      }
    }
    
    if (!state.DHs || !state.DHs.key) {
      console.error('ratchetDecrypt: state.DHs.key is missing!');
    } else if (!(state.DHs.key instanceof Uint8Array || state.DHs.key instanceof ArrayBuffer)) {
      console.error('ratchetDecrypt: state.DHs.key is not a Uint8Array or ArrayBuffer:', state.DHs.key);
    }
    
    try {
      const dhsPubB64 = state.DHs && state.DHs.pub ? CryptoUtils.bytesToBase64(state.DHs.pub) : 'null';
      const dhsKeyBytes = state.DHs && state.DHs.key ? Array.from(new Uint8Array(state.DHs.key).slice(0,4)).map(b=>b.toString(16)).join(' ') : 'null';
      const dhrB64 = state.DHr ? CryptoUtils.bytesToBase64(state.DHr) : 'null';
      const headerDhB64 = header && header.dh ? CryptoUtils.bytesToBase64(header.dh) : 'null';
      console.log(`ratchetDecrypt: DHs.pub=${dhsPubB64}, DHs.key[0-3]=${dhsKeyBytes}, DHr=${dhrB64}, header.dh=${headerDhB64}`);
      if (state.DHs && state.DHs.pub) {
        console.log(`ratchetDecrypt: DHs.pub (hex): ${Array.from(state.DHs.pub).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
      if (state.DHs && state.DHs.key) {
        console.log(`ratchetDecrypt: DHs.key (hex): ${Array.from(new Uint8Array(state.DHs.key)).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
      if (state.DHr) {
        console.log(`ratchetDecrypt: DHr (hex): ${Array.from(state.DHr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
      if (header && header.dh) {
        console.log(`ratchetDecrypt: header.dh (hex): ${Array.from(header.dh).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      }
    } catch (e) {
      console.error('ratchetDecrypt: error logging DH keys', e);
    }

    console.log(`ratchetDecrypt: Original header.dh type=${typeof header.dh}, value=${header.dh}`);
    if (typeof header.dh === 'string') {
      try {
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(header.dh)) {
          console.error(`ratchetDecrypt: Invalid base64 characters in header.dh: ${header.dh}`);
          throw new Error(`Invalid base64 format in header.dh`);
        }
        header.dh = CryptoUtils.base64ToBytes(header.dh);
        console.log(`ratchetDecrypt: Successfully converted header.dh from base64, length=${header.dh.length}`);
        console.log(`ratchetDecrypt: header.dh (hex): ${Array.from(header.dh).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      } catch (error) {
        console.error(`ratchetDecrypt: Failed to convert header.dh from base64:`, error);
        console.error(`ratchetDecrypt: header.dh string:`, header.dh);
        throw new Error(`Invalid header.dh format: ${error.message}`);
      }
    }
    
    if (state.DHr && typeof state.DHr === 'string') {
      try {
        state.DHr = CryptoUtils.base64ToBytes(state.DHr);
        console.log('ratchetDecrypt: Converted state.DHr from base64 to Uint8Array');
      } catch (e) {
        console.error('ratchetDecrypt: Failed to convert state.DHr from base64:', e);
      }
    }
    
    console.log(`ratchetDecrypt: header.dh type=${Object.prototype.toString.call(header.dh)}, length=${header.dh.length}`);
    console.log(`ratchetDecrypt: state.DHr type=${Object.prototype.toString.call(state.DHr)}, length=${state.DHr ? state.DHr.length : 'null'}`);
    
    if (header.dh && state.DHr) {
      console.log(`ratchetDecrypt: header.dh (full hex): ${Array.from(header.dh).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: state.DHr (full hex): ${Array.from(state.DHr).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: header.dh [0-7]: ${Array.from(header.dh.slice(0,8)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: state.DHr [0-7]: ${Array.from(state.DHr.slice(0,8)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    }
    
    let forceDHRatchet = false;
    if (state.expectNextDH) {
      forceDHRatchet = true;
      console.log('ratchetDecrypt: Forcing DH ratchet due to expectNextDH flag (receiver just sent new DH key pair)');
      delete state.expectNextDH;
    }
    
    function bytesEqual(a, b) {
      if (!a || !b || a.length !== b.length) return false;
      for (let i = 0; i < a.length; ++i) if (a[i] !== b[i]) return false;
      return true;
    }
    const isNewDH = header.dh && state.DHr && !bytesEqual(header.dh, state.DHr);
    
    console.log(`🔍 ratchetDecrypt: DEBUG - Current state:`);
    console.log(`  - state.CKr: ${state.CKr ? 'initialized' : 'null'}`);
    console.log(`  - state.CKs: ${state.CKs ? 'initialized' : 'null'}`);
    console.log(`  - state.Ns: ${state.Ns}, state.Nr: ${state.Nr}`);
    console.log(`  - forceDHRatchet: ${forceDHRatchet}, isNewDH: ${isNewDH}`);
    console.log(`  - header.dh: ${header.dh ? 'present' : 'null'}`);
    console.log(`  - state.DHr: ${state.DHr ? 'present' : 'null'}`);
    console.log(`  - state object keys: ${Object.keys(state)}`);
    if (state.CKr) {
      console.log(`  - state.CKr type: ${Object.prototype.toString.call(state.CKr)}, length: ${state.CKr.length}`);
    }
    
    let mk, ckr;
    
    if (state.Nr === 0 && !isNewDH) {
      console.log('ratchetDecrypt: First message detected with same DH, skipping DH ratchet and using existing CKr');
      
      if (!state.CKr) {
        console.log('ratchetDecrypt: CKr is null, this should not happen for the first message');
        console.log('ratchetDecrypt: CKr should have been initialized during session establishment');
        console.error('ratchetDecrypt: Session state:', {
          CKs: !!state.CKs,
          CKr: !!state.CKr,
          DHs: !!state.DHs,
          DHr: !!state.DHr,
          Ns: state.Ns,
          Nr: state.Nr
        });
        throw new Error('Receiving chain key (CKr) is not initialized. Session initialization failed.');
      }
      
      console.log('ratchetDecrypt: Using existing CKr for first message decryption');
      [ckr, mk] = await SessionManager.chainKDF(state.CKr);
      console.log(`ratchetDecrypt: mk (hex): ${Array.from(mk).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: ckr (hex): ${Array.from(ckr).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    } else if (forceDHRatchet || isNewDH) {
      if (forceDHRatchet) {
        console.log('ratchetDecrypt: Performing forced DH ratchet (protocol correction)');
      } else {
        console.log(`ratchetDecrypt: New header.dh detected, performing DH ratchet. Updating DHr and chain keys.`);
      }
      await SessionManager.skipMessageKeys(state, header.pn, maxSkip);
      await SessionManager.DHRatchet(state, header);
      console.log(`ratchetDecrypt: After DHRatchet - New DHr (hex): ${Array.from(state.DHr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: After DHRatchet - New CKr (hex): ${Array.from(state.CKr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: After DHRatchet - New CKs (hex): ${state.CKs ? Array.from(state.CKs).map(b=>b.toString(16).padStart(2,'0')).join(' ') : 'null'}`);
      console.log(`ratchetDecrypt: After DHRatchet - New DHs.key[0-3]: ${Array.from(state.DHs.key.slice(0,4)).map(b=>b.toString(16)).join(' ')}`);
      if (!state.CKr) {
        console.error('ratchetDecrypt: CKr is still null after DH ratchet. This should not happen.');
        throw new Error('Receiving chain key (CKr) is not initialized after DH ratchet. Session initialization failed.');
      }
      [ckr, mk] = await SessionManager.chainKDF(state.CKr);
      console.log(`ratchetDecrypt: mk derived from new CKr (hex): ${Array.from(mk).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: ckr from new CKr (hex): ${Array.from(ckr).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    } else {
      console.log(`ratchetDecrypt: No DH ratchet needed, using current CKr.`);
      
      if (!state.CKr) {
        console.error('ratchetDecrypt: CKr is null, cannot derive message key');
        throw new Error('Receiving chain key (CKr) is not initialized');
      }
      [ckr, mk] = await SessionManager.chainKDF(state.CKr);
      console.log(`ratchetDecrypt: mk (hex): ${Array.from(mk).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
      console.log(`ratchetDecrypt: ckr (hex): ${Array.from(ckr).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    }
    console.log(`ratchetDecrypt: mk[0-3]=${Array.from(mk.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}, ckr[0-3]=${Array.from(ckr.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`ratchetDecrypt: CKr after chainKDF: ${state.CKr ? Array.from(state.CKr).map(b => b.toString(16).padStart(2,'0')).join(' ') : 'null'}`);

    console.log(`ratchetDecrypt: CHAIN KEY ADVANCEMENT:`);
    console.log(`  - CKr before chainKDF: ${state.CKr ? Array.from(state.CKr).map(b=>b.toString(16).padStart(2,'0')).join(' ') : 'null'}`);
    console.log(`  - mk derived from CKr: ${Array.from(mk).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - ckr (new CKr): ${Array.from(ckr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - Order: CKr -> mk -> ckr (correct)`);

    const logHeaderForKDF = {
      dh: CryptoUtils.bytesToBase64(header.dh),
      pn: header.pn,
      n: header.n
    };
    const logHeaderString = CryptoUtils.serializeHeader(logHeaderForKDF);
    const logHeaderBytes = CryptoUtils.textToBytes(logHeaderString);
    console.log(`ratchetDecrypt: header string: ${logHeaderString}`);
    console.log(`ratchetDecrypt: headerBytes (hex): ${Array.from(logHeaderBytes).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`ratchetDecrypt: AD (hex): ${Array.from(ad).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const logCombinedBytes = CryptoUtils.combine(mk, logHeaderBytes);
    console.log(`ratchetDecrypt: KDF input (mk+headerBytes) (hex): ${Array.from(logCombinedBytes).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const logHeaderForKDFClone = JSON.parse(JSON.stringify(logHeaderForKDF));

    console.log(`ratchetDecrypt: CKr type=${typeof state.CKr}, length=${state.CKr ? state.CKr.length : 0}`);
    if (state.CKr) console.log(`ratchetDecrypt: CKr (hex): ${Array.from(state.CKr).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);

    const found = await SessionManager.trySkippedMessageKeys(
      state, header, ciphertext, ad
    );
    if (found) {
      return found;
    }

    await SessionManager.skipMessageKeys(state, header.n, maxSkip);
    
    const headerForKDF = {
      dh: CryptoUtils.bytesToBase64(header.dh),
      pn: header.pn,
      n: header.n
    };
    const headerString = CryptoUtils.serializeHeader(headerForKDF);
    const headerBytes = CryptoUtils.textToBytes(headerString);
    console.log(`ratchetDecrypt: header string: ${headerString}`);
    console.log(`ratchetDecrypt: headerBytes (hex): ${Array.from(headerBytes).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    const combinedBytes = CryptoUtils.combine(mk, headerBytes);
    console.log(`ratchetDecrypt: mk[0-3]=${Array.from(mk.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}, headerBytes length=${headerBytes.length}`);
    console.log(`ratchetDecrypt: combinedBytes[0-3]=${Array.from(combinedBytes.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);

    const key = await KDF.derive(
      combinedBytes,
      new Uint8Array(32),
      CryptoUtils.textToBytes('ENCRYPT'),
      256
    );
    
    if (CryptoUtils.serializeHeader(headerForKDF) !== headerString) {
      console.error('ratchetDecrypt: headerForKDF mutated after KDF!');
    }

    const reconstructedHeader = {
      dh: CryptoUtils.bytesToBase64(header.dh),
      pn: header.pn,
      n: header.n
    };
    const reconstructedHeaderString = CryptoUtils.serializeHeader(reconstructedHeader);
    console.log(`ratchetDecrypt: HEADER COMPARISON:`);
    console.log(`  - Original header string: ${headerString}`);
    console.log(`  - Reconstructed header string: ${reconstructedHeaderString}`);
    console.log(`  - Headers match: ${headerString === reconstructedHeaderString}`);

    const ciphertextBase64Before = CryptoUtils.bytesToBase64(ciphertext);
    console.log(`ratchetDecrypt: CIPHERTEXT BEFORE DECRYPT (base64):`, ciphertextBase64Before);
    
    if (header && header._debugCiphertextB64) {
      if (header._debugCiphertextB64 !== ciphertextBase64Before) {
        console.warn('ratchetDecrypt: WARNING - Ciphertext base64 does not match what was output by encrypt! Possible mutation or encoding issue.');
        console.warn(`  - header._debugCiphertextB64: ${header._debugCiphertextB64}`);
        console.warn(`  - ciphertextBase64Before:    ${ciphertextBase64Before}`);
      } else {
        console.log('ratchetDecrypt: Ciphertext base64 matches encrypt output.');
      }
    }
    console.log(`ratchetDecrypt: About to call AEAD.decrypt with:`);
    console.log(`  - key length: ${key.length}, key[0-3]: ${Array.from(key.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - ad length: ${ad.length}, ad[0-3]: ${Array.from(ad.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - ciphertext length: ${ciphertext.length}, ciphertext[0-3]: ${Array.from(ciphertext.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    let decrypted;
    try {
      decrypted = await AEAD.decrypt(ciphertext, key, ad);
      console.log(`ratchetDecrypt: PLAINTEXT AFTER DECRYPT:`, decrypted);
      delete state.init;
    } catch (error) {
      console.error(`ratchetDecrypt: AES-GCM decryption failed:`, error);
      console.error(`ratchetDecrypt: Error name:`, error.name);
      console.error(`ratchetDecrypt: Error message:`, error.message);
      console.error(`ratchetDecrypt: Error stack:`, error.stack);
      console.error(`ratchetDecrypt: Key used for decryption:`, Array.from(key).map(b => b.toString(16).padStart(2,'0')).join(' '));
      console.error(`ratchetDecrypt: AD used for decryption:`, Array.from(ad).map(b => b.toString(16).padStart(2,'0')).join(' '));
      console.error(`ratchetDecrypt: Ciphertext length:`, ciphertext.length);
      console.error(`ratchetDecrypt: Ciphertext[0-15]:`, Array.from(ciphertext.slice(0,16)).map(b => b.toString(16).padStart(2,'0')).join(' '));
      throw error;
    }

    if (CryptoUtils.serializeHeader(header) !== originalHeaderString) {
      console.error('ratchetDecrypt: header mutated after AEAD!');
    }

    console.log(`ratchetDecrypt: DECRYPTION VALUES:`);
    console.log(`  - mk (message key): ${Array.from(mk).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - header string: ${headerString}`);
    console.log(`  - header bytes: ${Array.from(headerBytes).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - AD: ${Array.from(ad).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - key (derived from mk+header): ${Array.from(key).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);
    console.log(`  - ciphertext: ${Array.from(ciphertext).map(b=>b.toString(16).padStart(2,'0')).join(' ')}`);

    console.log(`ratchetDecrypt: BEFORE ADVANCE mk=${Array.from(mk).map(b=>b.toString(16).padStart(2,'0')).join(' ')}, ckr=${state.CKr ? Array.from(state.CKr).map(b=>b.toString(16).padStart(2,'0')).join(' ') : 'null'}`);
    
    state.Nr += 1;
    state.CKr = ckr;
    
    console.log(`ratchetDecrypt: AFTER ADVANCE ckr=${Array.from(state.CKr).map(b=>b.toString(16).padStart(2,'0')).join(' ')}, Nr=${state.Nr}`);
    console.log(`ratchetDecrypt: STATE AFTER: Ns=${state.Ns}, Nr=${state.Nr}, CKs=${state.CKs ? Array.from(state.CKs).map(b=>b.toString(16)).join(' ') : 'null'}, CKr=${state.CKr ? Array.from(state.CKr).map(b=>b.toString(16)).join(' ') : 'null'}, DHs.pub=${state.DHs && state.DHs.pub ? CryptoUtils.bytesToBase64(state.DHs.pub) : 'null'}, DHr=${state.DHr ? CryptoUtils.bytesToBase64(state.DHr) : 'null'}`);

    return {
      header,
      plaintext: JSON.parse(decrypted)
    };
  }
}

class EnvelopeEncryption {
  static async sealEnvelope(user, to, message) {
    const ek = await ECDHKeyPair.generate();
    const dh1 = await ECDHKeyPair.deriveFromBytes(ek.key, to);
    
    const sbits = await KDF.derive(
      dh1,
      new Uint8Array(32),
      CryptoUtils.textToBytes('SEAL'),
      512
    );

    const sealkey = sbits.slice(0, 32);
    const chainkey = sbits.slice(32, 64);
    const sealAD = CryptoUtils.combine(ek.pub, to);
    
    const seal = await AEAD.encrypt(
      CryptoUtils.bytesToBase64(user.pub),
      sealkey,
      sealAD
    );

    const dh2 = await ECDHKeyPair.deriveFromBytes(user.key, to);
    const mbits = await KDF.derive(
      dh2,
      chainkey,
      CryptoUtils.textToBytes('MESSAGE'),
      256
    );

    const msgkey = mbits;
    const msgAD = CryptoUtils.combine(user.pub, to);
    
    const ciphertext = await AEAD.encrypt(
      JSON.stringify(message),
      msgkey,
      msgAD
    );

    return {
      type: 'envelope',
      to: to,
      ek: ek.pub,
      seal: seal,
      ciphertext: ciphertext
    };
  }

  static async openEnvelope(user, envelope) {
    const dh1 = await ECDHKeyPair.deriveFromBytes(user.key, envelope.ek);
    
    const sbits = await KDF.derive(
      dh1,
      new Uint8Array(32),
      CryptoUtils.textToBytes('SEAL'),
      512
    );

    const sealkey = sbits.slice(0, 32);
    const chainkey = sbits.slice(32, 64);
    const sealAD = CryptoUtils.combine(envelope.ek, user.pub);
    
    const from = await AEAD.decrypt(envelope.seal, sealkey, sealAD);
    const fromBytes = CryptoUtils.base64ToBytes(from);
    
    const dh2 = await ECDHKeyPair.deriveFromBytes(user.key, fromBytes);
    const mbits = await KDF.derive(
      dh2,
      chainkey,
      CryptoUtils.textToBytes('MESSAGE'),
      256
    );

    const msgkey = mbits;
    const msgAD = CryptoUtils.combine(fromBytes, user.pub);
    
    const decrypted = await AEAD.decrypt(envelope.ciphertext, msgkey, msgAD);

    return {
      type: 'envelope',
      to: envelope.to,
      from: fromBytes,
      plaintext: JSON.parse(decrypted)
    };
  }
}

class Session {
  constructor(sessionData) {
    this.sessionState = sessionData;
    if (!this.sessionState.state && this.sessionState.userInstance) {
      this.sessionState.state = {};
      this.sessionState.state.userInstance = this.sessionState.userInstance;
    }
    if (!this.sessionState.userInstance && !(this.sessionState.state && this.sessionState.state.userInstance)) {
      throw new Error('Session must be created via User.createSession, User.openSession, or User.loadSession so that userInstance is set.');
    }
  }

  to() {
    return CryptoUtils.deepClone(this.sessionState.user);
  }

  async send(message) {
    const state = CryptoUtils.deepClone(this.sessionState.state);
    
    console.log(`Session.send: local type=${typeof this.sessionState.local}, remote type=${typeof this.sessionState.remote}`);
    console.log(`Session.send: local length=${this.sessionState.local ? this.sessionState.local.length : 0}, remote length=${this.sessionState.remote ? this.sessionState.remote.length : 0}`);
    if (this.sessionState.local) console.log(`Session.send: local[0-3]=${Array.from(this.sessionState.local.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    if (this.sessionState.remote) console.log(`Session.send: remote[0-3]=${Array.from(this.sessionState.remote.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const localPub = this.sessionState.local || new Uint8Array(65);
    const remotePub = this.sessionState.remote || new Uint8Array(65);
    const cmp = compareUint8Arrays(localPub, remotePub);
    const fullAD = cmp < 0
      ? CryptoUtils.combine(localPub, remotePub)
      : CryptoUtils.combine(remotePub, localPub);
    console.log(`Session.send: fullAD type=${Object.prototype.toString.call(fullAD)}, length=${fullAD.length}, [0-3]=${Array.from(fullAD.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    // Sign the message (as JSON string) with the sender's ECDSA key
    const messageString = JSON.stringify(message);
    const userInstance = this.sessionState.userInstance || (this.sessionState.state && this.sessionState.state.userInstance);
    if (!userInstance || typeof userInstance.sign !== 'function') {
      throw new Error('Session does not have a valid userInstance for signing');
    }
    const signature = await userInstance.sign(messageString);
    
    const payload = await SessionManager.ratchetEncrypt(
      state,
      message,
      fullAD,
      this.sessionState.init || null
    );
    // Attach signature (base64) to the payload
    payload.signature = CryptoUtils.bytesToBase64(signature);
    payload.to = this.sessionState.user.toString();
    this.sessionState.state = CryptoUtils.deepClone(state);
    return payload;
  }

  async read(payload) {
    const state = CryptoUtils.deepClone(this.sessionState.state);
    
    console.log(`Session.read: local type=${typeof this.sessionState.local}, remote type=${typeof this.sessionState.remote}`);
    console.log(`Session.read: local length=${this.sessionState.local ? this.sessionState.local.length : 0}, remote length=${this.sessionState.remote ? this.sessionState.remote.length : 0}`);
    if (this.sessionState.local) console.log(`Session.read: local[0-3]=${Array.from(this.sessionState.local.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    if (this.sessionState.remote) console.log(`Session.read: remote[0-3]=${Array.from(this.sessionState.remote.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const localPub = this.sessionState.local || new Uint8Array(65);
    const remotePub = this.sessionState.remote || new Uint8Array(65);
    const cmp = compareUint8Arrays(localPub, remotePub);
    const fullAD = cmp < 0
      ? CryptoUtils.combine(localPub, remotePub)
      : CryptoUtils.combine(remotePub, localPub);
    console.log(`Session.read: fullAD type=${Object.prototype.toString.call(fullAD)}, length=${fullAD.length}, [0-3]=${Array.from(fullAD.slice(0,4)).map(b => b.toString(16).padStart(2,'0')).join(' ')}`);
    
    const decrypted = await SessionManager.ratchetDecrypt(
      state,
      payload,
      fullAD
    );
    // After decryption, verify the signature
    let signatureValid = false;
    let signatureError = null;
    try {
      if (payload.signature) {
        // Use remoteECDSAPub from session state
        const pubKeyBytes = this.sessionState.remoteECDSAPub;
        if (!pubKeyBytes) throw new Error('No remote ECDSA public key available');
        const pubKey = await ECDSAKeyPair.importPublicKey(pubKeyBytes);
        const messageString = JSON.stringify(decrypted.plaintext);
        const signatureBytes = CryptoUtils.base64ToBytes(payload.signature);
        signatureValid = await Encryption.verify(pubKey, messageString, signatureBytes);
      } else {
        signatureError = 'No signature present in payload';
      }
    } catch (err) {
      signatureValid = false;
      signatureError = err.message || err;
    }

    if (this.sessionState.init) {
      delete this.sessionState.init;
    }

    const msg = {
      header: payload.header,
      plaintext: decrypted.plaintext,
      from: this.to(),
      signatureValid,
      signatureError
    };

    this.sessionState.state = CryptoUtils.deepClone(state);
    return msg;
  }

  save() {
    const backup = {
      state: CryptoUtils.deepClone(this.sessionState.state)
    };

    if (this.sessionState.init) {
      backup.init = CryptoUtils.deepClone(this.sessionState.init);
    }
    if (this.sessionState.user) {
      backup.user = CryptoUtils.deepClone(this.sessionState.user);
    }
    if (this.sessionState.AD) {
      backup.AD = CryptoUtils.deepClone(this.sessionState.AD);
    }

    return backup;
  }
}

class User {
  constructor(userData) {
    this.userState = CryptoUtils.deepClone(userData);
  }

  async createOPK() {
    const secret = await ECDHKeyPair.generate();
    const card = {
      user: this.userState.pub,
      opk: secret.pub,
      ecdsa: this.userState.ecdsa.pub // Always include ECDSA public key
    };
    return { card, secret };
  }

  async sealEnvelope(to, message) {
    return await EnvelopeEncryption.sealEnvelope(this.userState, to, message);
  }

  async openEnvelope(envelope) {
    return await EnvelopeEncryption.openEnvelope(this.userState, envelope);
  }

  async createSession(card) {
    const session = await this.createSessionData(this.userState, card);
    session.state = await SessionManager.createInitRatchet(session);
    delete session.sk;
    session.userInstance = this;
    if (session.state) session.state.userInstance = this;
    // Debug: Log initial CKs and CKr after session establishment (initiator)
    if (session.state) {
      console.log('[DEBUG] Initiator session CKs:', Array.from(session.state.CKs || []).map(b => b.toString(16).padStart(2, '0')).join(' '));
      console.log('[DEBUG] Initiator session CKr:', Array.from(session.state.CKr || []).map(b => b.toString(16).padStart(2, '0')).join(' '));
    }
    return new Session(session);
  }

  async openSession(init, secretOPK) {
    const session = await this.openSessionData(this.userState, secretOPK, init);
    session.state = await SessionManager.openInitRatchet(session, secretOPK);
    delete session.sk;
    session.userInstance = this;
    if (session.state) session.state.userInstance = this;
    // Debug: Log initial CKs and CKr after session establishment (responder)
    if (session.state) {
      console.log('[DEBUG] Responder session CKs:', Array.from(session.state.CKs || []).map(b => b.toString(16).padStart(2, '0')).join(' '));
      console.log('[DEBUG] Responder session CKr:', Array.from(session.state.CKr || []).map(b => b.toString(16).padStart(2, '0')).join(' '));
    }
    return new Session(session);
  }

  async loadSession(sessionData) {
    sessionData.userInstance = this;
    if (sessionData.state) sessionData.state.userInstance = this;
    return new Session(sessionData);
  }

  save() {
    return CryptoUtils.deepClone(this.userState);
  }

  getID() {
    return this.userState && this.userState.pub ? new Uint8Array(this.userState.pub) : new Uint8Array();
  }

  async createSessionData(user, card) {
    const eph = await ECDHKeyPair.generate();
    const opkPubKey = await ECDHKeyPair.importPublicKey(card.opk); // Import as CryptoKey
    // --- FIXED TRIPLE-DH ORDER ---
    // dh1 = ECDH(eph.privateKey, card.user)
    // dh2 = ECDH(user.key, opkPubKey)
    // dh3 = ECDH(eph.privateKey, opkPubKey)
    const dh1 = await ECDHKeyPair.derive(eph.privateKey, await ECDHKeyPair.importPublicKey(card.user));
    const dh2 = await ECDHKeyPair.derive(await ECDHKeyPair.importPrivateKey(user.key), opkPubKey);
    const dh3 = await ECDHKeyPair.derive(eph.privateKey, opkPubKey);
    const combined = CryptoUtils.combine(CryptoUtils.combine(dh1, dh2), dh3);
    console.log('[DEBUG] createSessionData:');
    console.log('  dh1:', Array.from(dh1.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  dh2:', Array.from(dh2.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  dh3:', Array.from(dh3.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  combined:', Array.from(combined.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    const sk = await KDF.derive(
      combined,
      new Uint8Array(32),
      CryptoUtils.textToBytes('SESSION'),
      256
    );
    console.log('  sk:', Array.from(sk.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    const AD = CryptoUtils.combine(user.pub, card.user);
    const init = {
      type: 'init',
      to: card.user,
      from: user.pub,
      epk: eph.pub,
      ecdsa: user.ecdsa.pub, // Always include initiator's ECDSA public key
      epkPrivate: eph.key,
      opk: card.opk
    };
    return {
      type: 'session',
      user: card.user,
      partner: user.pub,
      local: user.pub,
      remote: card.user,
      sk,
      AD,
      init,
      remoteECDSAPub: card.ecdsa
    };
  }

  async openSessionData(user, opk, init) {
    console.log(`[DEBUG] openSessionData:`);
    // dh1 = ECDH(user.key, init.epk)
    // dh2 = ECDH(opk.key, init.from)
    // dh3 = ECDH(opk.key, init.epk)
    const dh1 = await ECDHKeyPair.deriveFromBytes(user.key, init.epk);
    const dh2 = await ECDHKeyPair.deriveFromBytes(opk.key, init.from);
    const dh3 = await ECDHKeyPair.deriveFromBytes(opk.key, init.epk);
    console.log('  dh1:', Array.from(dh1.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  dh2:', Array.from(dh2.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    console.log('  dh3:', Array.from(dh3.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    const combined = CryptoUtils.combine(CryptoUtils.combine(dh1, dh2), dh3);
    console.log('  combined:', Array.from(combined.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    const sk = await KDF.derive(
      combined,
      new Uint8Array(32),
      CryptoUtils.textToBytes('SESSION'),
      256
    );
    console.log('  sk:', Array.from(sk.slice(0,8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));
    // ... existing code ...
    const localPub = user.pub && user.pub.length === 65 ? user.pub : new Uint8Array(65);
    const partnerPub = init.from && init.from.length === 65 ? init.from : new Uint8Array(65);
    const AD = CryptoUtils.combine(
      localPub < partnerPub ? localPub : partnerPub,
      localPub < partnerPub ? partnerPub : localPub
    );
    return {
      type: 'session',
      user: init.from,
      partner: user.pub,
      local: user.pub,
      remote: init.from,
      sk,
      AD,
      init,
      remoteECDSAPub: init.ecdsa
    };
  }

  static async createWithECDSA() {
    // Generate ECDH keypair (for encryption)
    const ecdhKeys = await ECDHKeyPair.generate();
    // Generate ECDSA keypair (for signing)
    const ecdsaKeys = await ECDSAKeyPair.generate();
    // Store both in userState
    const userData = {
      ...ecdhKeys,
      ecdsa: {
        pub: ecdsaKeys.pub,
        key: ecdsaKeys.key
      }
    };
    return new User(userData);
  }

  async getECDSAPublicKey() {
    if (!this.userState.ecdsa || !this.userState.ecdsa.pub) throw new Error('No ECDSA public key');
    return await ECDSAKeyPair.importPublicKey(this.userState.ecdsa.pub);
  }

  async getECDSAPrivateKey() {
    if (!this.userState.ecdsa || !this.userState.ecdsa.key) throw new Error('No ECDSA private key');
    return await ECDSAKeyPair.importPrivateKey(this.userState.ecdsa.key);
  }

  async sign(message) {
    const privateKey = await this.getECDSAPrivateKey();
    const data = CryptoUtils.textToBytes(message);
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      privateKey,
      data
    );
    return new Uint8Array(signature);
  }

  async verify(message, signature) {
    const publicKey = await this.getECDSAPublicKey();
    const data = CryptoUtils.textToBytes(message);
    return await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      publicKey,
      signature,
      data
    );
  }
}

class Encryption {
  static async createUser() {
    // Use User.createWithECDSA to generate both ECDH and ECDSA keys
    return await User.createWithECDSA();
  }

  static async loadUser(userData) {
    return new User(userData);
  }

  static cloneState(src) {
    return CryptoUtils.deepClone(src);
  }

  static async sign(privateKey, message) {
    const key = (privateKey instanceof CryptoKey)
      ? privateKey
      : await ECDSAKeyPair.importPrivateKey(privateKey);
    const data = CryptoUtils.textToBytes(message);
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      key,
      data
    );
    return new Uint8Array(signature);
  }

  static async verify(publicKey, message, signature) {
    const key = (publicKey instanceof CryptoKey)
      ? publicKey
      : await ECDSAKeyPair.importPublicKey(publicKey);
    const data = CryptoUtils.textToBytes(message);
    return await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' }
      },
      key,
      signature,
      data
    );
  }
}

// --- ECDSA Key Management ---
class ECDSAKeyPair {
  static async generate() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );
    const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const privateKeyBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      pub: publicKeyBytes,
      key: privateKeyBytes
    };
  }

  static async importPublicKey(publicKeyBytes) {
    if (publicKeyBytes instanceof Uint8Array) {
      publicKeyBytes = publicKeyBytes.buffer;
    }
    return await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['verify']
    );
  }

  static async importPrivateKey(privateKeyBytes) {
    if (privateKeyBytes instanceof Uint8Array) {
      privateKeyBytes = privateKeyBytes.buffer;
    }
    return await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBytes,
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign']
    );
  }
}

// Add this helper function near the top (after CryptoUtils)
function compareUint8Arrays(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); ++i) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

// Export for Node.js
if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Encryption;
}

// Export for browser
if (typeof window !== 'undefined') {
  window.Encryption = Encryption;
} 