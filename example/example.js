/**
 * Practical Example: Secure Chat Application
 * 
 * This example demonstrates how to build a simple secure chat system
 * using the Nudge library.
 */

const Encryption = require('./encryption.js');

class SecureChat {
  constructor() {
    this.users = new Map();
    this.sessions = new Map();
  }

  /**
   * Register a new user
   * @param {string} username - User's display name
   * @returns {Promise<Object>} - User data and ID
   */
  async registerUser(username) {
    const user = await Encryption.createUser();
    const userData = {
      username,
      user: user,
      id: user.getID()
    };
    
    this.users.set(username, userData);
    console.log(`✅ User "${username}" registered with ID: ${userData.id.length} bytes`);
    
    return userData;
  }

  /**
   * Create a pre-key for session establishment
   * @param {string} username - Username who creates the pre-key
   * @returns {Promise<Object>} - Pre-key card and secret
   */
  async createPreKey(username) {
    const userData = this.users.get(username);
    if (!userData) {
      throw new Error(`User "${username}" not found`);
    }

    const { card, secret } = await userData.user.createOPK();
    console.log(`🔑 Pre-key created for "${username}"`);
    
    return { card, secret, username };
  }

  /**
   * Establish a session between two users
   * @param {string} initiator - Username initiating the session
   * @param {string} recipient - Username receiving the session
   * @param {Object} preKeyData - Pre-key data from createPreKey
   * @returns {Promise<Object>} - Session information
   */
  async establishSession(initiator, recipient, preKeyData) {
    const initiatorData = this.users.get(initiator);
    const recipientData = this.users.get(recipient);
    
    if (!initiatorData || !recipientData) {
      throw new Error('One or both users not found');
    }

    // Recipient creates session using initiator's pre-key
    const recipientSession = await recipientData.user.createSession(preKeyData.card);
    
    // Initiator opens session using their secret
    const initiatorSession = await initiatorData.user.openSession(
      recipientSession.save().init, 
      preKeyData.secret
    );

    // Store sessions
    const sessionId = `${initiator}-${recipient}`;
    this.sessions.set(sessionId, {
      initiator: initiatorSession,
      recipient: recipientSession,
      initiatorName: initiator,
      recipientName: recipient
    });

    console.log(`🤝 Session established between "${initiator}" and "${recipient}"`);
    
    return {
      sessionId,
      initiator: initiatorSession,
      recipient: recipientSession
    };
  }

  /**
   * Send a message through an established session
   * @param {string} sender - Username sending the message
   * @param {string} recipient - Username receiving the message
   * @param {Object} message - Message content
   * @returns {Promise<Object>} - Encrypted message payload
   */
  async sendMessage(sender, recipient, message) {
    // Try both possible session key formats
    const sessionId1 = `${sender}-${recipient}`;
    const sessionId2 = `${recipient}-${sender}`;
    let session = this.sessions.get(sessionId1);
    
    if (!session) {
      session = this.sessions.get(sessionId2);
    }
    
    if (!session) {
      throw new Error(`No session found between "${sender}" and "${recipient}"`);
    }

    // Determine which session to use based on sender
    const sessionToUse = session.initiatorName === sender ? 
      session.initiator : session.recipient;

    const payload = await sessionToUse.send({
      text: message,
      sender: sender,
      timestamp: Date.now()
    });
    // Log signature
    if (payload.signature) {
      console.log(`   Signature (base64): ${payload.signature}`);
    }
    console.log(`📤 Message sent from "${sender}" to "${recipient}"`);
    return payload;
  }

  /**
   * Receive and decrypt a message
   * @param {string} recipient - Username receiving the message
   * @param {string} sender - Username who sent the message
   * @param {Object} payload - Encrypted message payload
   * @returns {Promise<Object>} - Decrypted message
   */
  async receiveMessage(recipient, sender, payload) {
    // Try both possible session key formats
    const sessionId1 = `${sender}-${recipient}`;
    const sessionId2 = `${recipient}-${sender}`;
    let session = this.sessions.get(sessionId1);
    
    if (!session) {
      session = this.sessions.get(sessionId2);
    }
    
    if (!session) {
      throw new Error(`No session found between "${sender}" and "${recipient}"`);
    }

    // Determine which session to use based on recipient
    const sessionToUse = session.recipientName === recipient ? 
      session.recipient : session.initiator;

    const decrypted = await sessionToUse.read(payload);
    // Log signature verification
    if (typeof decrypted.signatureValid !== 'undefined') {
      if (decrypted.signatureValid) {
        console.log(`   ✅ Signature verified for message from "${sender}" to "${recipient}"`);
      } else {
        console.log(`   ❌ Signature verification failed: ${decrypted.signatureError}`);
      }
    }
    console.log(`📥 Message received by "${recipient}" from "${sender}"`);
    return decrypted;
  }

  /**
   * Save session state for persistence
   * @param {string} sessionId - Session identifier
   * @returns {Object} - Session backup data
   */
  saveSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session "${sessionId}" not found`);
    }

    return {
      sessionId,
      initiator: session.initiator.save(),
      recipient: session.recipient.save(),
      initiatorName: session.initiatorName,
      recipientName: session.recipientName
    };
  }

  /**
   * Load session state from backup
   * @param {Object} sessionData - Session backup data
   * @returns {Promise<Object>} - Restored session
   */
  async loadSession(sessionData) {
    const initiatorData = this.users.get(sessionData.initiatorName);
    const recipientData = this.users.get(sessionData.recipientName);
    
    if (!initiatorData || !recipientData) {
      throw new Error('One or both users not found for session restoration');
    }

    const initiatorSession = await initiatorData.user.loadSession(sessionData.initiator);
    const recipientSession = await recipientData.user.loadSession(sessionData.recipient);

    this.sessions.set(sessionData.sessionId, {
      initiator: initiatorSession,
      recipient: recipientSession,
      initiatorName: sessionData.initiatorName,
      recipientName: sessionData.recipientName
    });

    console.log(`🔄 Session "${sessionData.sessionId}" restored`);
    
    return {
      sessionId: sessionData.sessionId,
      initiator: initiatorSession,
      recipient: recipientSession
    };
  }
}

// Example usage
async function runExample() {
  console.log('🚀 Starting Secure Chat Example\n');

  const chat = new SecureChat();

  try {
    // 1. Register users
    console.log('📝 Registering users...');
    await chat.registerUser('Alice');
    await chat.registerUser('Bob');
    await chat.registerUser('Charlie');
    console.log();

    // 2. Create pre-keys for session establishment
    console.log('🔑 Creating pre-keys...');
    const alicePreKey = await chat.createPreKey('Alice');
    const bobPreKey = await chat.createPreKey('Bob');
    console.log();

    // 3. Establish sessions
    console.log('🤝 Establishing sessions...');
    const aliceBobSession = await chat.establishSession('Alice', 'Bob', alicePreKey);
    const bobCharlieSession = await chat.establishSession('Bob', 'Charlie', bobPreKey);
    console.log();

    // 4. Send messages
    console.log('💬 Sending messages...');
    
    // Alice sends message to Bob
    const message1 = await chat.sendMessage('Alice', 'Bob', 'Hello Bob! How are you?');
    
    // Bob receives Alice's message
    const received1 = await chat.receiveMessage('Bob', 'Alice', message1);
    console.log(`   Bob received: "${received1.plaintext.text}"`);
    
    // Bob replies to Alice
    const message2 = await chat.sendMessage('Bob', 'Alice', 'Hi Alice! I\'m doing great, thanks!');
    
    // Alice receives Bob's reply
    const received2 = await chat.receiveMessage('Alice', 'Bob', message2);
    console.log(`   Alice received: "${received2.plaintext.text}"`);
    
    // Bob sends message to Charlie
    const message3 = await chat.sendMessage('Bob', 'Charlie', 'Hey Charlie! Welcome to the chat!');
    
    // Charlie receives Bob's message
    const received3 = await chat.receiveMessage('Charlie', 'Bob', message3);
    console.log(`   Charlie received: "${received3.plaintext.text}"`);
    console.log();

    // 5. Demonstrate session persistence
    console.log('💾 Testing session persistence...');
    const sessionBackup = chat.saveSession('Alice-Bob');
    
    // Simulate application restart by clearing sessions
    chat.sessions.clear();
    console.log('   Sessions cleared (simulating restart)');
    
    // Restore session
    await chat.loadSession(sessionBackup);
    
    // Test communication after restoration
    const message4 = await chat.sendMessage('Alice', 'Bob', 'This message is sent after session restoration!');
    const received4 = await chat.receiveMessage('Bob', 'Alice', message4);
    console.log(`   Bob received after restoration: "${received4.plaintext.text}"`);
    console.log();

    // 6. Test long message chains
    console.log('🔗 Testing Long Message Chains...');
    const chainLength = 25; // Test with 25 messages in each direction
    
    // Alice sends a long chain to Bob
    console.log(`   Alice → Bob chain (${chainLength} messages):`);
    const aliceToBobMessages = [];
    for (let i = 1; i <= chainLength; i++) {
      const message = await chat.sendMessage('Alice', 'Bob', `Alice's message ${i} of ${chainLength}`);
      aliceToBobMessages.push(message);
    }
    
    // Bob receives the long chain
    const bobReceivedMessages = [];
    for (let i = 0; i < chainLength; i++) {
      const received = await chat.receiveMessage('Bob', 'Alice', aliceToBobMessages[i]);
      bobReceivedMessages.push(received);
    }
    
    // Verify Alice → Bob chain
    let aliceBobSuccess = true;
    for (let i = 0; i < chainLength; i++) {
      const expectedText = `Alice's message ${i + 1} of ${chainLength}`;
      if (bobReceivedMessages[i].plaintext.text !== expectedText) {
        aliceBobSuccess = false;
        console.log(`   ❌ Alice → Bob chain failed at message ${i + 1}`);
        break;
      }
    }
    
    if (aliceBobSuccess) {
      console.log(`   ✅ Alice → Bob chain successful (${chainLength} messages)`);
    }
    
    // Bob sends a long chain to Alice
    console.log(`   Bob → Alice chain (${chainLength} messages):`);
    const bobToAliceMessages = [];
    for (let i = 1; i <= chainLength; i++) {
      const message = await chat.sendMessage('Bob', 'Alice', `Bob's message ${i} of ${chainLength}`);
      bobToAliceMessages.push(message);
    }
    
    // Alice receives the long chain
    const aliceReceivedMessages = [];
    for (let i = 0; i < chainLength; i++) {
      const received = await chat.receiveMessage('Alice', 'Bob', bobToAliceMessages[i]);
      aliceReceivedMessages.push(received);
    }
    
    // Verify Bob → Alice chain
    let bobAliceSuccess = true;
    for (let i = 0; i < chainLength; i++) {
      const expectedText = `Bob's message ${i + 1} of ${chainLength}`;
      if (aliceReceivedMessages[i].plaintext.text !== expectedText) {
        bobAliceSuccess = false;
        console.log(`   ❌ Bob → Alice chain failed at message ${i + 1}`);
        break;
      }
    }
    
    if (bobAliceSuccess) {
      console.log(`   ✅ Bob → Alice chain successful (${chainLength} messages)`);
    }
    
    // Test alternating conversation pattern
    console.log(`   Alternating conversation pattern (${chainLength} messages):`);
    const alternatingMessages = [];
    for (let i = 1; i <= chainLength; i++) {
      const sender = i % 2 === 0 ? 'Alice' : 'Bob';
      const recipient = sender === 'Alice' ? 'Bob' : 'Alice';
      const message = await chat.sendMessage(sender, recipient, `Alternating message ${i} from ${sender}`);
      alternatingMessages.push({ message, sender, recipient });
    }
    
    // Receive alternating messages
    let alternatingSuccess = true;
    for (let i = 0; i < chainLength; i++) {
      const { message, sender, recipient } = alternatingMessages[i];
      const received = await chat.receiveMessage(recipient, sender, message);
      const expectedText = `Alternating message ${i + 1} from ${sender}`;
      
      if (received.plaintext.text !== expectedText) {
        alternatingSuccess = false;
        console.log(`   ❌ Alternating pattern failed at message ${i + 1}`);
        break;
      }
    }
    
    if (alternatingSuccess) {
      console.log(`   ✅ Alternating conversation successful (${chainLength} messages)`);
    }
    
    if (aliceBobSuccess && bobAliceSuccess && alternatingSuccess) {
      console.log(`   ✅ Long message chain testing successful (${chainLength * 3} total messages)`);
    } else {
      throw new Error('Long message chain testing failed');
    }
    console.log();

    console.log('🎉 Secure Chat Example completed successfully!');
    console.log('\n📊 Summary:');
    console.log('   ✅ User registration and management');
    console.log('   ✅ Pre-key creation and session establishment');
    console.log('   ✅ Secure message sending and receiving');
    console.log('   ✅ Session persistence and restoration');
    console.log('   ✅ Multi-user chat functionality');
    console.log('   ✅ Long message chain testing');

  } catch (error) {
    console.error('❌ Example failed:', error);
    console.error('Stack trace:', error.stack);
  }
}

// Run example if this file is executed directly
if (require.main === module) {
  runExample();
}

module.exports = { SecureChat, runExample }; 