/**
 * Nudge - Secure Encryption Library
 * 
 * - ECDH key exchange
 * - Double ratchet algorithm for forward secrecy
 * - Envelope encryption for secure messaging
 * - Session management with state persistence
 * - SECURE: No cryptographic material logging
 * 
 * @author thejordanprice
 * @version 2.1.0
 */

'use strict';

// Security configuration
const SECURITY_CONFIG = {
  MAX_SKIP_MESSAGES: 10,
  KEY_LENGTH: 32,
  IV_LENGTH: 12,
  SALT_LENGTH: 32,
  MAX_MESSAGE_SIZE: 1024 * 1024, // 1MB
  RATE_LIMIT_WINDOW: 60000, // 1 minute
  RATE_LIMIT_MAX_REQUESTS: 100
};

// Rate limiting for security
const rateLimitMap = new Map();

/**
 * Utility functions for encoding/decoding and cryptographic operations
 */
class CryptoUtils {
  static textToBytes(text) {
    if (typeof text !== 'string') {
      throw new TypeError('CryptoUtils.textToBytes: text must be a string');
    }
    return new TextEncoder().encode(text);
  }

  static bytesToText(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError('CryptoUtils.bytesToText: bytes must be Uint8Array');
    }
    return new TextDecoder().decode(bytes);
  }

  static bytesToBase64(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError('CryptoUtils.bytesToBase64: bytes must be Uint8Array');
    }
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i] & 0xff);
    }
    return btoa(binary);
  }

  static base64ToBytes(base64) {
    if (typeof base64 !== 'string') {
      throw new TypeError('CryptoUtils.base64ToBytes: base64 must be a string');
    }
    // Validate base64 format
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
      throw new Error('CryptoUtils.base64ToBytes: Invalid base64 format');
    }
    try {
      const binary = atob(base64);
      return new Uint8Array([...binary].map(char => char.charCodeAt(0)));
    } catch (error) {
      throw new Error('CryptoUtils.base64ToBytes: Failed to decode base64');
    }
  }

  static combine(...arrays) {
    if (!arrays.every(arr => arr instanceof Uint8Array)) {
      throw new TypeError('CryptoUtils.combine: All arguments must be Uint8Array');
    }
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
    if (typeof length !== 'number' || length <= 0 || length > 65536) {
      throw new TypeError('CryptoUtils.randomBytes: length must be a positive number <= 65536');
    }
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

  // Constant-time comparison to prevent timing attacks
  static constantTimeEqual(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
      return false;
    }
    if (a.length !== b.length) {
      return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  // Secure input validation
  static validateKey(key, expectedLength = SECURITY_CONFIG.KEY_LENGTH) {
    if (!(key instanceof Uint8Array) || key.length !== expectedLength) {
      throw new Error(`Invalid key: expected Uint8Array of length ${expectedLength}`);
    }
    return true;
  }

  static validateMessage(message) {
    if ((typeof message !== 'string' && typeof message !== 'object') || message === null) {
      throw new TypeError('Message must be a string or object');
    }
    const messageStr = typeof message === 'string' ? message : JSON.stringify(message);
    if (messageStr.length > SECURITY_CONFIG.MAX_MESSAGE_SIZE) {
      throw new Error('Message too large');
    }
    return true;
  }

  // Rate limiting
  static checkRateLimit(identifier) {
    const now = Date.now();
    const windowStart = now - SECURITY_CONFIG.RATE_LIMIT_WINDOW;
    
    if (!rateLimitMap.has(identifier)) {
      rateLimitMap.set(identifier, []);
    }
    
    const requests = rateLimitMap.get(identifier);
    const validRequests = requests.filter(timestamp => timestamp > windowStart);
    
    if (validRequests.length >= SECURITY_CONFIG.RATE_LIMIT_MAX_REQUESTS) {
      throw new Error('Rate limit exceeded');
    }
    
    validRequests.push(now);
    rateLimitMap.set(identifier, validRequests);
    
    // Clean up old entries
    if (rateLimitMap.size > 1000) {
      for (const [key, timestamps] of rateLimitMap.entries()) {
        const validTimestamps = timestamps.filter(timestamp => timestamp > windowStart);
        if (validTimestamps.length === 0) {
          rateLimitMap.delete(key);
        } else {
          rateLimitMap.set(key, validTimestamps);
        }
      }
    }
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
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      pub: publicKeyBytes,
      key: privateKeyBytes
    };
  }

  static async importPublicKey(publicKeyBytes) {
    if (!(publicKeyBytes instanceof Uint8Array)) {
      throw new TypeError('ECDHKeyPair.importPublicKey: publicKeyBytes must be Uint8Array');
    }
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
    if (!(privateKeyBytes instanceof Uint8Array)) {
      throw new TypeError('ECDHKeyPair.importPrivateKey: privateKeyBytes must be Uint8Array');
    }
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
    if (!(inputKeyMaterial instanceof Uint8Array)) {
      throw new TypeError('KDF.derive: inputKeyMaterial must be Uint8Array');
    }
    if (!(salt instanceof Uint8Array)) {
      throw new TypeError('KDF.derive: salt must be Uint8Array');
    }
    if (!(info instanceof Uint8Array)) {
      throw new TypeError('KDF.derive: info must be Uint8Array');
    }
    if (typeof length !== 'number' || length <= 0) {
      throw new TypeError('KDF.derive: length must be a positive number');
    }

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
    if (!(key instanceof Uint8Array)) {
      throw new TypeError('KDF.hmac: key must be Uint8Array');
    }
    if (!(data instanceof Uint8Array)) {
      throw new TypeError('KDF.hmac: data must be Uint8Array');
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
    CryptoUtils.validateKey(key);
    if (!(associatedData instanceof Uint8Array)) {
      throw new Error('AEAD.encrypt: associatedData must be Uint8Array');
    }
    CryptoUtils.validateMessage(plaintext);
    

    
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

    const iv = CryptoUtils.randomBytes(SECURITY_CONFIG.IV_LENGTH);
    const encodedPlaintext = CryptoUtils.textToBytes(plaintext);
    
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: associatedData
      },
      cryptoKey,
      encodedPlaintext
    );

    return CryptoUtils.combine(iv, new Uint8Array(ciphertext));
  }

  static async decrypt(ciphertext, key, associatedData) {
    CryptoUtils.validateKey(key);
    if (!(associatedData instanceof Uint8Array)) {
      throw new Error('AEAD.decrypt: associatedData must be Uint8Array');
    }
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length < SECURITY_CONFIG.IV_LENGTH) {
      throw new Error(`AEAD.decrypt: Invalid ciphertext length ${ciphertext ? ciphertext.length : 'undefined'}, expected at least ${SECURITY_CONFIG.IV_LENGTH} bytes`);
    }
    

    
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
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ciphertext.slice(0, SECURITY_CONFIG.IV_LENGTH),
          additionalData: associatedData
        },
        cryptoKey,
        ciphertext.slice(SECURITY_CONFIG.IV_LENGTH)
      );

      return CryptoUtils.bytesToText(new Uint8Array(decrypted));
    } catch (error) {
      throw new Error('AEAD.decrypt: Decryption failed - invalid ciphertext or key');
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
    
    const dh = await ECDHKeyPair.deriveFromBytes(state.DHs.key, state.DHr);
    const [rk, ck] = await SessionManager.rootKDF(session.sk, dh);
    state.RK = rk;
    state.CKs = ck instanceof Uint8Array ? ck : new Uint8Array(ck);
    state.CKr = null;
    

    
    return state;
  }

  static async openInitRatchet(session, opk) {
    if (session.sk && opk && opk.key && opk.pub && session.init && session.init.epk) {
      const dh = await ECDHKeyPair.deriveFromBytes(opk.key, session.init.epk);
      const [rk, ck] = await SessionManager.rootKDF(session.sk, dh);
      session.sk = rk;
      const state = {
        DHs: opk,
        DHr: session.init.epk,
        RK: session.sk,
        CKs: null,
        CKr: ck instanceof Uint8Array ? ck : new Uint8Array(ck),
        Ns: 0,
        Nr: 0,
        PN: 0,
        MKSKIPPED: {}
      };
      
      
      
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
    const mk = await KDF.hmac(ck, CryptoUtils.textToBytes('MESSAGE'));
    const cks = await KDF.hmac(ck, CryptoUtils.textToBytes('CHAIN'));
    

    
    return [cks, mk];
  }

  static async trySkippedMessageKeys(state, header, ciphertext, aead) {
    if (state.MKSKIPPED && state.MKSKIPPED[header.n]) {
      const mk = state.MKSKIPPED[header.n];
      delete state.MKSKIPPED[header.n];
      return await aead.decrypt(ciphertext, mk, header);
    }
    return null;
  }

  static async skipMessageKeys(state, until, maxSkip = SECURITY_CONFIG.MAX_SKIP_MESSAGES) {
    if (state.Nr + maxSkip < until) {
      throw new Error('Too many skipped messages');
    }
    
    if (state.CKr) {
      while (state.Nr < until) {
        const [ckr, mk] = await SessionManager.chainKDF(state.CKr);
        state.MKSKIPPED[state.Nr] = mk;
        state.CKr = ckr;
        state.Nr += 1;
      }
    }
  }

  static async DHRatchet(state, header) {
    const dh = await ECDHKeyPair.deriveFromBytes(state.DHs.key, header.dh);
    const [rk, ck] = await SessionManager.rootKDF(state.RK, dh);
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;
    state.DHr = header.dh;
    state.RK = rk;
    state.CKr = ck;
    state.MKSKIPPED = {};
  }

  static async ratchetEncrypt(state, message, ad, init) {
    if (!state.CKs) {
      throw new Error('ratchetEncrypt: No sending chain key');
    }
    
    const [cks, mk] = await SessionManager.chainKDF(state.CKs);
    
    const header = {
      dh: CryptoUtils.bytesToBase64(state.DHs.pub),
      pn: state.PN,
      n: state.Ns
    };
    
    const headerString = CryptoUtils.serializeHeader(header);
    const headerBytes = CryptoUtils.textToBytes(headerString);
    
    const combinedBytes = CryptoUtils.combine(mk, headerBytes);
    
    const key = await KDF.derive(
      combinedBytes,
      new Uint8Array(SECURITY_CONFIG.SALT_LENGTH),
      CryptoUtils.textToBytes('ENCRYPT'),
      256
    );



    const ciphertext = await AEAD.encrypt(
      JSON.stringify(message),
      key,
      ad
    );
    
    state.Ns += 1;
    state.CKs = cks;
    
    const encrypted = { header, ciphertext };
    if (init) {
      encrypted.init = CryptoUtils.deepClone(init);
    }

    return encrypted;
  }

  static async ratchetDecrypt(state, msgPayload = {}, ad, maxSkip = SECURITY_CONFIG.MAX_SKIP_MESSAGES) {
    const { ciphertext } = msgPayload;
    const header = CryptoUtils.deepClone(msgPayload.header);
    
    // Convert ciphertext from base64 to bytes if it's a string
    let ciphertextBytes = ciphertext;
    if (typeof ciphertext === 'string') {
      try {
        ciphertextBytes = CryptoUtils.base64ToBytes(ciphertext);
      } catch (error) {
        throw new Error(`Invalid ciphertext format: ${error.message}`);
      }
    }
    
    if (header && header.dh) {
      if (typeof header.dh === 'string') {
        try {
          header.dh = CryptoUtils.base64ToBytes(header.dh);
        } catch (error) {
          throw new Error(`Invalid header.dh format: ${error.message}`);
        }
      }
    }
    
    if (state.DHr && typeof state.DHr === 'string') {
      try {
        state.DHr = CryptoUtils.base64ToBytes(state.DHr);
      } catch (e) {
        throw new Error('Failed to convert state.DHr from base64');
      }
    }
    
    let forceDHRatchet = false;
    if (state.expectNextDH) {
      forceDHRatchet = true;
      delete state.expectNextDH;
    }
    
    function bytesEqual(a, b) {
      return CryptoUtils.constantTimeEqual(a, b);
    }
    
    const isNewDH = header.dh && state.DHr && !bytesEqual(header.dh, state.DHr);
    
    if (isNewDH || forceDHRatchet) {
      await SessionManager.DHRatchet(state, header);
    }
    
    await SessionManager.skipMessageKeys(state, header.n, maxSkip);
    
    if (!state.CKr) {
      throw new Error('ratchetDecrypt: No receiving chain key');
    }
    
    const [ckr, mk] = await SessionManager.chainKDF(state.CKr);
    
    // Use the original header from payload for serialization to maintain base64 format
    const headerString = CryptoUtils.serializeHeader(msgPayload.header);
    const headerBytes = CryptoUtils.textToBytes(headerString);
    
    const combinedBytes = CryptoUtils.combine(mk, headerBytes);
    
    const key = await KDF.derive(
      combinedBytes,
      new Uint8Array(SECURITY_CONFIG.SALT_LENGTH),
      CryptoUtils.textToBytes('ENCRYPT'),
      256
    );
    

    
    const plaintext = await AEAD.decrypt(ciphertextBytes, key, ad);
    const decrypted = JSON.parse(plaintext);
    
    state.Nr += 1;
    state.CKr = ckr;
    
    return { plaintext: decrypted };
  }
}

class EnvelopeEncryption {
  static async sealEnvelope(user, to, message) {
    CryptoUtils.validateMessage(message);
    CryptoUtils.checkRateLimit(`envelope_${user.pub ? Array.from(user.pub.slice(0, 8)).join('') : 'unknown'}`);
    
    const session = await user.createSession(to);
    const encrypted = await session.send(message);
    return encrypted;
  }

  // FIX: Accept secretOPK as third argument and pass to user.openSession
  static async openEnvelope(user, envelope, secretOPK) {
    CryptoUtils.checkRateLimit(`envelope_${user.pub ? Array.from(user.pub.slice(0, 8)).join('') : 'unknown'}`);
    
    const session = await user.openSession(envelope.init, secretOPK);
    const decrypted = await session.read(envelope);
    return decrypted;
  }
}

class Session {
  constructor(sessionData) {
    this.sessionState = CryptoUtils.deepClone(sessionData);
  }

  to() {
    return this.sessionState.user;
  }

  async send(message) {
    CryptoUtils.validateMessage(message);
    CryptoUtils.checkRateLimit(`session_send_${this.sessionState.user ? Array.from(this.sessionState.user.slice(0, 8)).join('') : 'unknown'}`);
    
    const state = this.sessionState.state;
    const ad = this.sessionState.AD;
    const fullAD = CryptoUtils.combine(ad, CryptoUtils.textToBytes('MESSAGE'));
    
    // If responder doesn't have sending chain key, perform DH ratchet to establish it
    if (!state.CKs && state.CKr) {
      // Generate new ephemeral key pair for DH ratchet
      const newEph = await ECDHKeyPair.generate();
      state.DHs = { pub: newEph.pub, key: newEph.key };
      
      // Perform DH ratchet to establish sending chain
      const dh = await ECDHKeyPair.deriveFromBytes(state.DHs.key, state.DHr);
      const [rk, ck] = await SessionManager.rootKDF(state.RK, dh);
      state.RK = rk;
      state.CKs = ck;
      state.PN = state.Ns;
      state.Ns = 0;
      state.Nr = 0;
    }
    
    const encrypted = await SessionManager.ratchetEncrypt(
      state,
      message,
      fullAD,
      this.sessionState.init
    );
    
    const signature = await this.sessionState.userInstance.sign(JSON.stringify(message));
    const signatureBase64 = CryptoUtils.bytesToBase64(signature);
    
    const payload = {
      header: encrypted.header,
      ciphertext: CryptoUtils.bytesToBase64(encrypted.ciphertext),
      signature: signatureBase64
    };
    
    if (encrypted.init) {
      payload.init = encrypted.init;
    }
    
    this.sessionState.state = CryptoUtils.deepClone(state);
    return payload;
  }

  async read(payload) {
    CryptoUtils.checkRateLimit(`session_read_${this.sessionState.user ? Array.from(this.sessionState.user.slice(0, 8)).join('') : 'unknown'}`);
    
    const state = this.sessionState.state;
    const ad = this.sessionState.AD;
    
    const fullAD = CryptoUtils.combine(ad, CryptoUtils.textToBytes('MESSAGE'));
    
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
      ecdsa: this.userState.ecdsa.pub
    };
    return { card, secret };
  }

  async sealEnvelope(to, message) {
    return await EnvelopeEncryption.sealEnvelope(this, to, message);
  }

  async openEnvelope(envelope, secretOPK) {
    return await EnvelopeEncryption.openEnvelope(this, envelope, secretOPK);
  }

  async createSession(card) {
    const session = await this.createSessionData(this.userState, card);
    session.state = await SessionManager.createInitRatchet(session);
    delete session.sk;
    const sessionInstance = new Session(session);
    sessionInstance.sessionState.userInstance = this;
    if (sessionInstance.sessionState.state) {
      sessionInstance.sessionState.state.userInstance = this;
    }
    return sessionInstance;
  }

  async openSession(init, secretOPK) {
    const session = await this.openSessionData(this.userState, secretOPK, init);
    session.state = await SessionManager.openInitRatchet(session, secretOPK);
    delete session.sk;
    const sessionInstance = new Session(session);
    sessionInstance.sessionState.userInstance = this;
    if (sessionInstance.sessionState.state) {
      sessionInstance.sessionState.state.userInstance = this;
    }
    return sessionInstance;
  }

  async loadSession(sessionData) {
    const sessionInstance = new Session(sessionData);
    sessionInstance.sessionState.userInstance = this;
    if (sessionInstance.sessionState.state) {
      sessionInstance.sessionState.state.userInstance = this;
    }
    return sessionInstance;
  }

  save() {
    return CryptoUtils.deepClone(this.userState);
  }

  getID() {
    return this.userState && this.userState.pub ? new Uint8Array(this.userState.pub) : new Uint8Array();
  }

  async createSessionData(user, card) {
    const eph = await ECDHKeyPair.generate();
    const opkPubKey = await ECDHKeyPair.importPublicKey(card.opk);
    
    const dh1 = await ECDHKeyPair.derive(eph.privateKey, await ECDHKeyPair.importPublicKey(card.user));
    const dh2 = await ECDHKeyPair.derive(await ECDHKeyPair.importPrivateKey(user.key), opkPubKey);
    const dh3 = await ECDHKeyPair.derive(eph.privateKey, opkPubKey);
    const combined = CryptoUtils.combine(CryptoUtils.combine(dh1, dh2), dh3);
    
    const sk = await KDF.derive(
      combined,
      new Uint8Array(SECURITY_CONFIG.SALT_LENGTH),
      CryptoUtils.textToBytes('SESSION'),
      256
    );
    
    const AD = CryptoUtils.combine(user.pub, card.user);

    const init = {
      type: 'init',
      to: card.user,
      from: user.pub,
      epk: eph.pub,
      ecdsa: user.ecdsa.pub,
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
    const dh1 = await ECDHKeyPair.deriveFromBytes(user.key, init.epk);
    const dh2 = await ECDHKeyPair.deriveFromBytes(opk.key, init.from);
    const dh3 = await ECDHKeyPair.deriveFromBytes(opk.key, init.epk);
    const combined = CryptoUtils.combine(CryptoUtils.combine(dh1, dh2), dh3);
    
    const sk = await KDF.derive(
      combined,
      new Uint8Array(SECURITY_CONFIG.SALT_LENGTH),
      CryptoUtils.textToBytes('SESSION'),
      256
    );
    
    const AD = CryptoUtils.combine(init.from, user.pub);

    

    
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
    const ecdhKeys = await ECDHKeyPair.generate();
    const ecdsaKeys = await ECDSAKeyPair.generate();
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
    if (!(publicKeyBytes instanceof Uint8Array)) {
      throw new TypeError('ECDSAKeyPair.importPublicKey: publicKeyBytes must be Uint8Array');
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
    if (!(privateKeyBytes instanceof Uint8Array)) {
      throw new TypeError('ECDSAKeyPair.importPrivateKey: privateKeyBytes must be Uint8Array');
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

// Export for Node.js
if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Encryption;
  // Also export security config and utilities for testing
  module.exports.SECURITY_CONFIG = SECURITY_CONFIG;
  module.exports.CryptoUtils = CryptoUtils;
}

// Export for browser
if (typeof window !== 'undefined') {
  window.Encryption = Encryption;
} 