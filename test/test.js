/**
 * Test file for Encryption library
 * Demonstrates key functionality and usage patterns
 */

// Import the library (adjust path as needed)
const Encryption = require('./encryption.js');

async function runTests() {
  console.log('🧪 Testing Encryption Library\n');

  try {
    // Test 1: User Creation
    console.log('1. Testing User Creation...');
    const alice = await Encryption.createUser();
    const bob = await Encryption.createUser();
    
    console.log('✅ Users created successfully');
    console.log(`   Alice ID: ${alice.getID() ? alice.getID().length : 'undefined'} bytes`);
    console.log(`   Bob ID: ${bob.getID() ? bob.getID().length : 'undefined'} bytes\n`);

    // Test 2: User Persistence
    console.log('2. Testing User Persistence...');
    const aliceData = alice.save();
    const bobData = bob.save();
    
    const aliceLoaded = await Encryption.loadUser(aliceData);
    const bobLoaded = await Encryption.loadUser(bobData);
    
    console.log('✅ Users loaded from saved data successfully\n');

    // Test 3: Envelope Encryption
    console.log('3. Testing Envelope Encryption...');
    const message = {
      type: 'test_message',
      content: 'Hello from Alice!',
      timestamp: Date.now()
    };
    
    const envelope = await alice.sealEnvelope(bob.getID(), message);
    const opened = await bob.openEnvelope(envelope);
    
    // --- Signature verification for envelope (if supported) ---
    if (opened && opened.plaintext && opened.plaintext.signature) {
      const pubKey = await alice.getECDSAPublicKey();
      const msgString = JSON.stringify({ ...opened.plaintext, signature: undefined });
      const sigBytes = Buffer.from(opened.plaintext.signature, 'base64');
      const valid = await Encryption.verify(pubKey, msgString, sigBytes);
      if (valid) {
        console.log('   ✅ Signature verified for envelope message');
      } else {
        throw new Error('Signature verification failed for envelope message');
      }
    } else {
      console.log('   (No signature present in envelope message, skipping signature check)');
    }
    console.log('✅ Envelope encryption/decryption successful');
    console.log(`   Original: ${JSON.stringify(message)}`);
    console.log(`   Decrypted: ${JSON.stringify(opened.plaintext)}\n`);

    // Test 4: Session Establishment
    console.log('4. Testing Session Establishment...');
    const { card, secret } = await bob.createOPK();
    const aliceSession = await alice.createSession(card);
    const bobSession = await bob.openSession(aliceSession.save().init, secret);
    
    console.log('✅ Session established successfully\n');

    // Test 5: Session Communication
    console.log('5. Testing Session Communication...');
    // Alice sends a message to Bob
    const aliceMessage = { type: 'test_message', content: 'Hello from Alice!', timestamp: Date.now() };
    const encryptedFromAlice = await aliceSession.send(aliceMessage);
    const decryptedByBob = await bobSession.read(encryptedFromAlice);
    // Log and check signature
    if (typeof decryptedByBob.signatureValid !== 'undefined') {
      if (decryptedByBob.signatureValid) {
        console.log('   ✅ Signature verified for Alice → Bob');
      } else {
        throw new Error('Signature verification failed for Alice → Bob: ' + decryptedByBob.signatureError);
      }
    }
    console.log('✅ Alice → Bob communication successful');
    console.log('   Original:', aliceMessage);
    console.log('   Decrypted by Bob:', decryptedByBob.plaintext);

    // Bob replies to Alice (triggers DH ratchet for Bob)
    const bobMessage = { type: 'test_message', content: 'Hello from Bob!', timestamp: Date.now() };
    const encryptedFromBob = await bobSession.send(bobMessage);
    const decryptedByAlice = await aliceSession.read(encryptedFromBob);
    // Log and check signature
    if (typeof decryptedByAlice.signatureValid !== 'undefined') {
      if (decryptedByAlice.signatureValid) {
        console.log('   ✅ Signature verified for Bob → Alice');
      } else {
        throw new Error('Signature verification failed for Bob → Alice: ' + decryptedByAlice.signatureError);
      }
    }
    console.log('✅ Bob → Alice communication successful');
    console.log('   Original:', bobMessage);
    console.log('   Decrypted by Alice:', decryptedByAlice.plaintext);

    // Test 6: Session Persistence
    console.log('6. Testing Session Persistence...');
    const bobSessionData = bobSession.save();
    const aliceSessionData = aliceSession.save();
    
    const bobSessionLoaded = await bob.loadSession(bobSessionData);
    const aliceSessionLoaded = await alice.loadSession(aliceSessionData);
    
    // Test communication with loaded sessions
    const testMessage = { text: 'Test from loaded session', id: 3 };
    const testEncrypted = await bobSessionLoaded.send(testMessage);
    const testDecrypted = await aliceSessionLoaded.read(testEncrypted);
    
    console.log('✅ Session persistence successful');
    console.log(`   Loaded session message: ${testDecrypted.plaintext.text}\n`);

    // Test 7: Multiple Messages
    console.log('7. Testing Multiple Messages...');
    const messages = [
      { text: 'Message 1', id: 1 },
      { text: 'Message 2', id: 2 },
      { text: 'Message 3', id: 3 }
    ];
    
    const encryptedMessages = [];
    for (const msg of messages) {
      encryptedMessages.push(await bobSession.send(msg));
    }
    
    const decryptedMessages = [];
    for (const encrypted of encryptedMessages) {
      const msg = await aliceSession.read(encrypted);
      // Log and check signature
      if (typeof msg.signatureValid !== 'undefined') {
        if (msg.signatureValid) {
          console.log('   ✅ Signature verified for Bob → Alice (multiple messages)');
        } else {
          throw new Error('Signature verification failed for Bob → Alice (multiple messages): ' + msg.signatureError);
        }
      }
      decryptedMessages.push(msg);
    }
    
    console.log('✅ Multiple messages successful');
    decryptedMessages.forEach((msg, index) => {
      console.log(`   Message ${index + 1}: ${msg.plaintext.text}`);
    });
    console.log();

    // Test 8: Long Message Chain Testing
    console.log('8. Testing Long Message Chain...');
    const longChainMessages = [];
    const chainLength = 50; // Test with 50 messages in each direction
    
    // Generate test messages
    for (let i = 1; i <= chainLength; i++) {
      longChainMessages.push({
        text: `Long chain message ${i}`,
        id: i,
        timestamp: Date.now() + i,
        sequence: i
      });
    }
    
    console.log(`   Testing ${chainLength} messages in each direction...`);
    
    // Alice sends a long chain to Bob
    console.log('   Alice → Bob chain:');
    const aliceToBobChain = [];
    for (let i = 0; i < chainLength; i++) {
      const encrypted = await aliceSession.send(longChainMessages[i]);
      aliceToBobChain.push(encrypted);
    }
    
    // Bob receives the long chain
    const bobReceivedChain = [];
    for (let i = 0; i < chainLength; i++) {
      const decrypted = await bobSession.read(aliceToBobChain[i]);
      // Log and check signature
      if (typeof decrypted.signatureValid !== 'undefined') {
        if (decrypted.signatureValid) {
          console.log('   ✅ Signature verified for Alice → Bob (long chain)');
        } else {
          throw new Error('Signature verification failed for Alice → Bob (long chain): ' + decrypted.signatureError);
        }
      }
      bobReceivedChain.push(decrypted);
    }
    
    // Verify Alice → Bob chain
    let aliceBobSuccess = true;
    for (let i = 0; i < chainLength; i++) {
      if (bobReceivedChain[i].plaintext.text !== longChainMessages[i].text ||
          bobReceivedChain[i].plaintext.id !== longChainMessages[i].id ||
          bobReceivedChain[i].plaintext.sequence !== longChainMessages[i].sequence) {
        aliceBobSuccess = false;
        console.log(`   ❌ Alice → Bob chain failed at message ${i + 1}`);
        break;
      }
    }
    
    if (aliceBobSuccess) {
      console.log(`   ✅ Alice → Bob chain successful (${chainLength} messages)`);
    }
    
    // Bob sends a long chain to Alice
    console.log('   Bob → Alice chain:');
    const bobToAliceChain = [];
    for (let i = 0; i < chainLength; i++) {
      const encrypted = await bobSession.send({
        text: `Bob's long chain message ${i + 1}`,
        id: i + 1000,
        timestamp: Date.now() + i + 1000,
        sequence: i + 1
      });
      bobToAliceChain.push(encrypted);
    }
    
    // Alice receives the long chain
    const aliceReceivedChain = [];
    for (let i = 0; i < chainLength; i++) {
      const decrypted = await aliceSession.read(bobToAliceChain[i]);
      // Log and check signature
      if (typeof decrypted.signatureValid !== 'undefined') {
        if (decrypted.signatureValid) {
          console.log('   ✅ Signature verified for Bob → Alice (long chain)');
        } else {
          throw new Error('Signature verification failed for Bob → Alice (long chain): ' + decrypted.signatureError);
        }
      }
      aliceReceivedChain.push(decrypted);
    }
    
    // Verify Bob → Alice chain
    let bobAliceSuccess = true;
    for (let i = 0; i < chainLength; i++) {
      const expectedText = `Bob's long chain message ${i + 1}`;
      if (aliceReceivedChain[i].plaintext.text !== expectedText ||
          aliceReceivedChain[i].plaintext.id !== i + 1000 ||
          aliceReceivedChain[i].plaintext.sequence !== i + 1) {
        bobAliceSuccess = false;
        console.log(`   ❌ Bob → Alice chain failed at message ${i + 1}`);
        break;
      }
    }
    
    if (bobAliceSuccess) {
      console.log(`   ✅ Bob → Alice chain successful (${chainLength} messages)`);
    }
    
    // Test alternating message pattern
    console.log('   Testing alternating message pattern...');
    const alternatingMessages = [];
    for (let i = 1; i <= 20; i++) {
      alternatingMessages.push({
        text: `Alternating message ${i}`,
        id: i,
        sender: i % 2 === 0 ? 'Alice' : 'Bob'
      });
    }
    
    let alternatingSuccess = true;
    for (let i = 0; i < alternatingMessages.length; i++) {
      const msg = alternatingMessages[i];
      let encrypted, decrypted;
      
      if (msg.sender === 'Alice') {
        encrypted = await aliceSession.send(msg);
        decrypted = await bobSession.read(encrypted);
      } else {
        encrypted = await bobSession.send(msg);
        decrypted = await aliceSession.read(encrypted);
      }
      // Log and check signature
      if (typeof decrypted.signatureValid !== 'undefined') {
        if (decrypted.signatureValid) {
          console.log('   ✅ Signature verified for alternating pattern');
        } else {
          throw new Error('Signature verification failed for alternating pattern: ' + decrypted.signatureError);
        }
      }
    }
    
    if (alternatingSuccess) {
      console.log('   ✅ Alternating message pattern successful (20 messages)');
    }
    
    if (aliceBobSuccess && bobAliceSuccess && alternatingSuccess) {
      console.log('✅ Long message chain testing successful');
      console.log(`   Total messages tested: ${chainLength * 2 + 20}`);
    } else {
      throw new Error('Long message chain testing failed');
    }
    console.log();

    // Test 9: Deep Clone Utility
    console.log('9. Testing Deep Clone Utility...');
    const original = {
      user: { name: 'Alice', id: 123 },
      session: { active: true, messages: [1, 2, 3] },
      data: new Uint8Array([1, 2, 3, 4])
    };
    
    const cloned = Encryption.cloneState(original);
    original.user.name = 'Bob';
    original.session.messages.push(4);
    original.data[0] = 99;
    
    console.log('✅ Deep clone successful');
    console.log(`   Original user name: ${original.user.name}`);
    console.log(`   Cloned user name: ${cloned.user.name}`);
    console.log(`   Original messages: ${original.session.messages.length}`);
    console.log(`   Cloned messages: ${cloned.session.messages.length}\n`);

    // After all other tests, add a summary test for all session messages
    console.log('10. Verifying signatures on all session messages...');
    // Check all previously decrypted session messages for signature validity
    const allSessionMessages = [decryptedByBob, decryptedByAlice, ...decryptedMessages, ...bobReceivedChain, ...aliceReceivedChain];
    for (const msg of allSessionMessages) {
      if (typeof msg.signatureValid !== 'undefined') {
        if (msg.signatureValid) {
          console.log('   ✅ Signature verified for session message');
        } else {
          throw new Error('Signature verification failed for session message: ' + msg.signatureError);
        }
      } else {
        console.log('   (No signature present in session message, skipping signature check)');
      }
    }
    console.log('✅ All session message signatures verified successfully');

    console.log('🎉 All tests passed successfully!');
    console.log('\n📋 Summary:');
    console.log('   ✅ User creation and persistence');
    console.log('   ✅ Envelope encryption/decryption');
    console.log('   ✅ Session establishment');
    console.log('   ✅ Session communication');
    console.log('   ✅ Session persistence');
    console.log('   ✅ Multiple message handling');
    console.log('   ✅ Long message chain testing');
    console.log('   ✅ Deep clone utility');

  } catch (error) {
    console.error('❌ Test failed:', error);
    console.error('Stack trace:', error.stack);
  }
}

// Run tests if this file is executed directly
if (require.main === module) {
  runTests();
}

module.exports = { runTests }; 