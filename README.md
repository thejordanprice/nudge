# Nudge - Secure End-to-End Encryption Library

A comprehensive JavaScript library for secure end-to-end encryption with forward secrecy, perfect forward secrecy, and digital signatures. Built with modern cryptographic standards and designed for both browser and Node.js environments.

## Features

- **ECDH Key Exchange**: Secure key agreement using P-256 elliptic curve
- **Double Ratchet Algorithm**: Forward secrecy with automatic key rotation
- **Envelope Encryption**: Secure messaging with sender anonymity
- **Digital Signatures**: ECDSA signatures for message authenticity
- **Session Management**: Persistent session state with secure serialization
- **Rate Limiting**: Built-in protection against abuse
- **Input Validation**: Comprehensive security checks
- **Constant-Time Operations**: Protection against timing attacks

## Security Features

### Forward Secrecy
The library implements the double ratchet algorithm, which provides forward secrecy by regularly rotating encryption keys. Even if a key is compromised, past messages remain secure.

### Perfect Forward Secrecy
Each message uses a unique key derived from the ratchet state, ensuring that compromising one message doesn't affect others.

### Envelope Encryption
Messages can be sealed in encrypted envelopes that hide the sender's identity until the envelope is opened by the intended recipient.

### Key Derivation
All keys are derived using HKDF (HMAC-based Key Derivation Function) with proper salting and context separation.

### Long Message Chain Support
The library has been extensively tested with long message chains (50+ messages) and alternating conversation patterns, ensuring robust performance for extended conversations.

### Digital Signatures
All session messages are digitally signed using ECDSA (P-256). The sender signs the plaintext before encryption, and the receiver verifies the signature after decryption. This ensures message authenticity and integrity in addition to confidentiality. Signature verification status is available in the result of `session.read()`.

### Security Hardening (v2.1.0)
- **No Cryptographic Material Logging**: Removed all debug logging of sensitive cryptographic data
- **Input Validation**: Comprehensive validation for all cryptographic operations
- **Constant-Time Comparisons**: Protection against timing attacks
- **Rate Limiting**: Built-in protection against abuse and DoS attacks
- **Configurable Security Parameters**: Adjustable limits and timeouts
- **Secure Error Handling**: No information leakage through error messages

## Installation

### Browser
```html
<script src="encryption.js"></script>
```

### Node.js
```bash
npm install nudge-encryption
```

## Quick Start

### Creating Users
```javascript
// Create a new user with both ECDH and ECDSA keys
const user = await Encryption.createUser();

// Save user data for later use
const userData = user.save();
```

### Establishing Sessions
```javascript
// User A creates a pre-key card
const { card, secret } = await userA.createOPK();

// User B creates a session using the card
const session = await userB.createSession(card);

// User A opens the session using the secret
const sessionA = await userA.openSession(session.init, secret);
```

### Sending Messages
```javascript
// Send an encrypted message
const payload = await session.send({
  text: "Hello, world!",
  timestamp: Date.now()
});

// The payload includes:
// - header: Ratchet state information
// - ciphertext: Encrypted message
// - signature: Digital signature
```

### Receiving Messages
```javascript
// Receive and decrypt a message
const message = await session.read(payload);

// message contains:
// - plaintext: The decrypted message object
// - signatureValid: Boolean indicating signature validity
// - signatureError: Error message if signature verification failed
```

## API Reference

### Encryption

Main library interface.

#### `Encryption.createUser()`
Creates a new user with ECDH and ECDSA key pairs.

**Returns:** `Promise<User>` - New user instance

#### `Encryption.loadUser(userData)`
Loads a user from saved data.

**Parameters:**
- `userData` (Object): Saved user data from `user.save()`

**Returns:** `Promise<User>` - Loaded user instance

#### `Encryption.cloneState(src)`
Creates a deep clone of session state.

**Parameters:**
- `src` (Object): Source state to clone

**Returns:** `Object` - Cloned state

#### `Encryption.sign(privateKey, message)`
Signs a message with an ECDSA private key.

**Parameters:**
- `privateKey` (CryptoKey|Uint8Array): ECDSA private key
- `message` (string): Message to sign

**Returns:** `Promise<Uint8Array>` - Digital signature

#### `Encryption.verify(publicKey, message, signature)`
Verifies an ECDSA signature.

**Parameters:**
- `publicKey` (CryptoKey|Uint8Array): ECDSA public key
- `message` (string): Original message
- `signature` (Uint8Array): Digital signature

**Returns:** `Promise<boolean>` - True if signature is valid

### User

Represents a user identity with cryptographic keys.

#### `user.createOPK()`
Creates a one-time pre-key for session establishment.

**Returns:** `Promise<Object>` - Pre-key card and secret

#### `user.sealEnvelope(to, message)`
Seals a message in an encrypted envelope.

**Parameters:**
- `to` (Uint8Array): Recipient's public key
- `message` (Object): Message to encrypt

**Returns:** `Promise<Object>` - Sealed envelope

#### `user.openEnvelope(envelope)`
Opens a sealed envelope and decrypts the message.

**Parameters:**
- `envelope` (Object): Sealed envelope from `sealEnvelope()`

**Returns:** `Promise<Object>` - Opened envelope with decrypted message

#### `user.createSession(card)`
Creates a new session using a pre-key card.

**Parameters:**
- `card` (Object): Pre-key card from `createOPK()`

**Returns:** `Promise<Session>` - New session

#### `user.openSession(init, secretOPK)`
Opens a session using initialization data and secret.

**Parameters:**
- `init` (Object): Session initialization data
- `secretOPK` (Object): One-time pre-key secret

**Returns:** `Promise<Session>` - Opened session

#### `user.loadSession(sessionData)`
Loads an existing session from saved data.

**Parameters:**
- `sessionData` (Object): Saved session data

**Returns:** `Promise<Session>` - Loaded session

#### `user.save()`
Saves the user's current state.

**Returns:** `Object` - User data for persistence

#### `user.getID()`
Gets the user's public key identifier.

**Returns:** `Uint8Array` - User's public key

### Session

Manages an encrypted session with another user.

#### `session.send(message)`
Sends an encrypted message through the session.

**Parameters:**
- `message` (Object): Message to encrypt and send

**Returns:** `Promise<Object>` - Encrypted payload (includes a digital signature)

#### `session.read(payload)`
Receives and decrypts a message from the session.

**Parameters:**
- `payload` (Object): Encrypted payload from `send()`

**Returns:** `Promise<Object>` - Decrypted message with metadata:
- `plaintext`: The decrypted message object
- `signatureValid`: `true` if the digital signature is valid, `false` otherwise
- `signatureError`: Error message if signature verification failed

#### `session.to()`
Gets the recipient's public key for this session.

**Returns:** `Uint8Array` - Recipient's public key

#### `session.save()`
Saves the session's current state.

**Returns:** `Object` - Session data for persistence

## Architecture

The library is organized into several focused classes:

- **CryptoUtils**: Utility functions for encoding, decoding, and data manipulation
- **ECDHKeyPair**: ECDH key pair generation and management
- **KDF**: Key derivation functions using HKDF and HMAC
- **AEAD**: Authenticated encryption with associated data using AES-GCM
- **SessionManager**: Double ratchet algorithm implementation
- **EnvelopeEncryption**: Envelope encryption for secure messaging
- **Session**: Session management and message encryption/decryption
- **User**: User identity and high-level operations
- **Encryption**: Main library interface

## Browser Compatibility

The library requires browsers with support for:
- Web Crypto API
- ES6+ features (async/await, classes, etc.)
- TextEncoder/TextDecoder

Modern browsers (Chrome 60+, Firefox 55+, Safari 11+, Edge 79+) are supported.

## Node.js Support

For Node.js environments, the library uses the built-in `crypto` module through the Web Crypto API polyfill or native support.

## Docker Usage

You can run the server in a Docker container. The provided Dockerfile will build an image that runs `server.js` and exposes port 8080.

### Build the Docker Image

```bash
docker build -t nudge .
```

### Run the Docker Container

```bash
docker run -p 8080:8080 nudge
```

This will start the server and map port 8080 of the container to port 8080 on your host machine.

## Development

### Running the Server
```bash
# Start the WebSocket server
npm run server
```

This will start the server on port 8080. You can then open `client.html` in your browser to test the chat application.

### Running Tests
```bash
# Node.js tests
npm test

# Browser tests
npm run test:browser
```

### Code Quality
```bash
# Linting
npm run lint

# Documentation
npm run docs
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Security Considerations

### Production Security Checklist
- [ ] Always use HTTPS in production
- [ ] Store private keys securely (hardware security modules recommended)
- [ ] Regularly rotate pre-keys
- [ ] Validate all inputs on both client and server
- [ ] Use secure random number generation (handled automatically)
- [ ] Implement proper key backup and recovery procedures
- [ ] Test thoroughly with long message chains for production use
- [ ] Monitor for rate limit violations
- [ ] Implement secure logging (no cryptographic material)
- [ ] Use constant-time operations for all comparisons

### Security Features Implemented
- **No Cryptographic Material Logging**: All debug logging of sensitive data has been removed
- **Input Validation**: Comprehensive validation for all cryptographic operations
- **Constant-Time Comparisons**: Protection against timing attacks
- **Rate Limiting**: Built-in protection against abuse (100 requests per minute per user)
- **Configurable Security Parameters**: Adjustable limits and timeouts
- **Secure Error Handling**: No information leakage through error messages
- **Message Size Limits**: Maximum message size of 1MB to prevent DoS
- **Key Length Validation**: Strict validation of cryptographic key lengths
- **Base64 Validation**: Proper validation of base64 encoded data

### Security Configuration
The library includes configurable security parameters:

```javascript
const SECURITY_CONFIG = {
  MAX_SKIP_MESSAGES: 10,        // Maximum messages to skip in ratchet
  KEY_LENGTH: 32,               // Cryptographic key length in bytes
  IV_LENGTH: 12,                // Initialization vector length
  SALT_LENGTH: 32,              // Salt length for key derivation
  MAX_MESSAGE_SIZE: 1024 * 1024, // Maximum message size (1MB)
  RATE_LIMIT_WINDOW: 60000,     // Rate limit window (1 minute)
  RATE_LIMIT_MAX_REQUESTS: 100  // Maximum requests per window
};
```

## Version History

### v2.1.0 (Security Release)
- **CRITICAL**: Removed all cryptographic material logging
- **SECURITY**: Added comprehensive input validation
- **SECURITY**: Implemented constant-time comparisons
- **SECURITY**: Added rate limiting protection
- **SECURITY**: Configurable security parameters
- **SECURITY**: Secure error handling
- **SECURITY**: Message size limits
- **SECURITY**: Key length validation
- **SECURITY**: Base64 format validation

### v2.0.0
- Enhanced long message chain support (50+ messages)
- Comprehensive test suite with browser and Node.js support
- Improved session management and state persistence
- Added practical chat application example
- Enhanced error handling and debugging capabilities 