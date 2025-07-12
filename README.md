# Encryption Library

A professional, modern JavaScript encryption library that provides end-to-end encryption with forward secrecy, perfect forward secrecy, and secure messaging capabilities. Built with native Web Crypto API and ES6+ features.

## Features

- **ECDH Key Exchange**: Elliptic Curve Diffie-Hellman key exchange using P-256 curve
- **Double Ratchet Algorithm**: Implements the Signal Protocol's double ratchet for forward secrecy
- **Envelope Encryption**: Secure envelope encryption for message delivery
- **Session Management**: Persistent session state with automatic key rotation
- **Long Message Chain Support**: Robust handling of extended conversations with 50+ messages
- **Zero Dependencies**: Uses only native Web Crypto API
- **Cross-Platform**: Works in browsers and Node.js environments
- **TypeScript Ready**: Full JSDoc documentation for TypeScript support
- **Comprehensive Testing**: Extensive test suite with browser and Node.js support
- **Digital Signatures**: All session messages are digitally signed and verified using ECDSA (P-256)

## Installation

### Browser
```html
<script src="encryption.js"></script>
```

### Node.js
```bash
npm install encryption-library
```

```javascript
const Encryption = require('./encryption.js');
```

## Quick Start

### Creating Users

```javascript
// Create a new user
const alice = await Encryption.createUser();
const bob = await Encryption.createUser();

// Save user data for later use
const aliceData = alice.save();
const bobData = bob.save();

// Load user from saved data
const aliceLoaded = await Encryption.loadUser(aliceData);
```

### Establishing Sessions

```javascript
// Bob creates a one-time pre-key for Alice
const { card, secret } = await bob.createOPK();

// Alice creates a session using Bob's pre-key
const aliceSession = await alice.createSession(card);

// Bob opens the session using his secret
const bobSession = await bob.openSession(aliceSession.save().init, secret);
```

### Sending Encrypted Messages

```javascript
// Alice sends a message to Bob
const message = { text: "Hello Bob!", timestamp: Date.now() };
const encryptedPayload = await aliceSession.send(message);

// Bob receives and decrypts the message
const decryptedMessage = await bobSession.read(encryptedPayload);
console.log(decryptedMessage.plaintext); // { text: "Hello Bob!", timestamp: ... }
// Check digital signature status
if (decryptedMessage.signatureValid) {
  console.log("Signature verified!");
} else {
  console.error("Signature verification failed:", decryptedMessage.signatureError);
}
```

### Envelope Encryption

```javascript
// Alice seals a message for Bob
const envelope = await alice.sealEnvelope(bob.getID(), {
  type: "direct_message",
  content: "This is a secure message"
});

// Bob opens the envelope
const opened = await bob.openEnvelope(envelope);
console.log(opened.plaintext); // { type: "direct_message", content: "This is a secure message" }
```

## Testing

The library includes comprehensive testing for both Node.js and browser environments.

### Node.js Testing
```bash
npm test
```

### Browser Testing
Open `test.html` in a modern browser to run the complete test suite.

### Test Coverage
- ✅ User creation and persistence
- ✅ Envelope encryption/decryption
- ✅ Session establishment and communication
- ✅ Session persistence and restoration
- ✅ Multiple message handling
- ✅ Long message chain testing (50+ messages)
- ✅ Alternating conversation patterns
- ✅ Deep clone utility functions

## Examples

### Complete Chat Application

See `example.js` for a full-featured secure chat application demonstrating:

- User registration and management
- Pre-key creation and session establishment
- Secure message sending and receiving
- Session persistence and restoration
- Multi-user chat functionality
- Long message chain testing (25+ messages in each direction)

```javascript
// Run the complete example
node example.js
```

### Basic Usage Example

```javascript
// Initialize users
const alice = await Encryption.createUser();
const bob = await Encryption.createUser();

// Establish session
const { card, secret } = await bob.createOPK();
const aliceSession = await alice.createSession(card);
const bobSession = await bob.openSession(aliceSession.save().init, secret);

// Send messages
const message1 = await bobSession.send({ text: "Hello Alice!" });
const message2 = await aliceSession.send({ text: "Hi Bob!" });

// Receive messages
const received1 = await aliceSession.read(message1);
const received2 = await bobSession.read(message2);

console.log(received1.plaintext.text); // "Hello Alice!"
console.log(received2.plaintext.text); // "Hi Bob!"
```

### Secure File Sharing

```javascript
const sender = await Encryption.createUser();
const recipient = await Encryption.createUser();

// Encrypt file data
const fileData = { name: "secret.txt", content: "sensitive data" };
const envelope = await sender.sealEnvelope(recipient.getID(), fileData);

// Decrypt file data
const decrypted = await recipient.openEnvelope(envelope);
console.log(decrypted.plaintext.name); // "secret.txt"
```

## API Reference

### Encryption

Main library class with static methods for user management.

#### `Encryption.createUser()`
Creates a new user with a fresh ECDH key pair.

**Returns:** `Promise<User>` - New user instance

#### `Encryption.loadUser(userData)`
Loads a user from saved user data.

**Parameters:**
- `userData` (Object): Saved user data from `user.save()`

**Returns:** `Promise<User>` - User instance

#### `Encryption.cloneState(src)`
Deep clones an object, useful for state management.

**Parameters:**
- `src` (*): Object to clone

**Returns:** * - Cloned object

### User

Represents a user identity with cryptographic operations.

#### `user.createOPK()`
Creates a one-time pre-key for session establishment.

**Returns:** `Promise<Object>` - `{ card, secret }` where `card` is the public pre-key and `secret` is the private key

#### `user.sealEnvelope(to, message)`
Seals a message in an encrypted envelope for a recipient.

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
docker build -t e2e-encryption .
```

### Run the Docker Container

```bash
docker run -p 8080:8080 e2e-encryption
```

This will start the server and map port 8080 of the container to port 8080 on your host machine.

## Development

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

- Always use HTTPS in production
- Store private keys securely
- Regularly rotate pre-keys
- Validate all inputs
- Use secure random number generation (handled automatically)
- Implement proper key backup and recovery procedures
- Test thoroughly with long message chains for production use

## Version History

### v2.0.0
- Enhanced long message chain support (50+ messages)
- Comprehensive test suite with browser and Node.js support
- Improved session management and state persistence
- Added practical chat application example
- Enhanced error handling and debugging capabilities 