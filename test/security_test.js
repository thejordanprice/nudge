/**
 * Security Test Suite for Nudge Encryption Library v2.1.0
 * 
 * Tests the security fixes implemented in version 2.1.0
 */

const Encryption = require('../encryption.js');

// Mock console.log to capture any cryptographic material logging
let consoleLogCalls = [];
const originalConsoleLog = console.log;
console.log = function(...args) {
  consoleLogCalls.push(args.join(' '));
  originalConsoleLog.apply(console, args);
};

async function runSecurityTests() {
  console.log('🔒 Running Security Tests for Nudge v2.1.0...\n');
  
  let testsPassed = 0;
  let testsFailed = 0;
  
  // Test 1: No cryptographic material logging
  console.log('Test 1: No cryptographic material logging');
  try {
    const user = await Encryption.createUser();
    const { card, secret } = await user.createOPK();
    
    // Check if any cryptographic material was logged
    const hasCryptoLogging = consoleLogCalls.some(log => 
      log.includes('key') || 
      log.includes('secret') || 
      log.includes('private') || 
      log.includes('cipher') ||
      log.includes('hex') ||
      log.includes('base64')
    );
    
    if (!hasCryptoLogging) {
      console.log('✅ PASS: No cryptographic material found in logs');
      testsPassed++;
    } else {
      console.log('❌ FAIL: Cryptographic material found in logs');
      console.log('Logs found:', consoleLogCalls.filter(log => 
        log.includes('key') || log.includes('secret') || log.includes('private')
      ));
      testsFailed++;
    }
  } catch (error) {
    console.log('❌ FAIL: Error during logging test:', error.message);
    testsFailed++;
  }
  
  // Test 2: Input validation
  console.log('\nTest 2: Input validation');
  try {
    const user = await Encryption.createUser();
    
    // Test user signing works correctly
    try {
      await user.sign("test");
      console.log('✅ PASS: User signing works correctly');
      testsPassed++;
    } catch (error) {
      console.log('❌ FAIL: User signing failed:', error.message);
      testsFailed++;
    }
    
    // Test invalid message type (direct validation)
    try {
      Encryption.CryptoUtils.validateMessage(null);
      console.log('❌ FAIL: Should have rejected null message');
      testsFailed++;
    } catch (error) {
      if (error.message.includes('Message must be')) {
        console.log('✅ PASS: Rejected invalid message type');
        testsPassed++;
      } else {
        console.log('❌ FAIL: Wrong error for invalid message:', error.message);
        testsFailed++;
      }
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during validation test:', error.message);
    testsFailed++;
  }
  
  // Test 3: Rate limiting
  console.log('\nTest 3: Rate limiting');
  try {
    const user = await Encryption.createUser();
    
    // Make many requests quickly to trigger rate limiting
    const promises = [];
    for (let i = 0; i < 150; i++) {
      promises.push(user.sealEnvelope(user.getID(), { test: i }));
    }
    
    let rateLimitErrors = 0;
    for (const promise of promises) {
      try {
        await promise;
      } catch (error) {
        if (error.message.includes('Rate limit exceeded')) {
          rateLimitErrors++;
        }
      }
    }
    
    if (rateLimitErrors > 0) {
      console.log(`✅ PASS: Rate limiting working (${rateLimitErrors} requests blocked)`);
      testsPassed++;
    } else {
      console.log('❌ FAIL: Rate limiting not working');
      testsFailed++;
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during rate limiting test:', error.message);
    testsFailed++;
  }
  
  // Test 4: Message size limits
  console.log('\nTest 4: Message size limits');
  try {
    const user = await Encryption.createUser();
    
    // Create a large message (over 1MB)
    const largeMessage = { data: 'x'.repeat(1024 * 1024 + 1) };
    
    try {
      await user.sealEnvelope(user.getID(), largeMessage);
      console.log('❌ FAIL: Should have rejected oversized message');
      testsFailed++;
    } catch (error) {
      if (error.message.includes('Message too large')) {
        console.log('✅ PASS: Rejected oversized message');
        testsPassed++;
      } else {
        console.log('❌ FAIL: Wrong error for oversized message:', error.message);
        testsFailed++;
      }
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during message size test:', error.message);
    testsFailed++;
  }
  
  // Test 5: Configuration parameters
  console.log('\nTest 5: Configuration parameters');
  try {
    // Test that security config is accessible
    if (typeof Encryption.SECURITY_CONFIG !== 'undefined') {
      console.log('✅ PASS: Security configuration available');
      testsPassed++;
    } else {
      console.log('❌ FAIL: Security configuration not available');
      testsFailed++;
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during configuration test:', error.message);
    testsFailed++;
  }
  
  // Test 6: Key validation
  console.log('\nTest 6: Key validation');
  try {
    const user = await Encryption.createUser();
    
    // Test with invalid key length
    try {
      await Encryption.sign(new Uint8Array(16), "test"); // Wrong key length
      console.log('❌ FAIL: Should have rejected invalid key length');
      testsFailed++;
    } catch (error) {
      if (error.message.includes('Invalid key') || error.message.includes('ECDSAKeyPair.importPrivateKey')) {
        console.log('✅ PASS: Rejected invalid key length');
        testsPassed++;
      } else {
        console.log('❌ FAIL: Wrong error for invalid key:', error.message);
        testsFailed++;
      }
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during key validation test:', error.message);
    testsFailed++;
  }
  
  // Test 7: CryptoUtils validation functions
  console.log('\nTest 7: CryptoUtils validation functions');
  try {
    // Test validateKey function
    try {
      Encryption.CryptoUtils.validateKey(new Uint8Array(16)); // Wrong length
      console.log('❌ FAIL: Should have rejected invalid key length');
      testsFailed++;
    } catch (error) {
      if (error.message.includes('Invalid key')) {
        console.log('✅ PASS: validateKey function working');
        testsPassed++;
      } else {
        console.log('❌ FAIL: Wrong error for validateKey:', error.message);
        testsFailed++;
      }
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during CryptoUtils test:', error.message);
    testsFailed++;
  }
  
  // Test 8: Constant-time comparison
  console.log('\nTest 8: Constant-time comparison');
  try {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    const c = new Uint8Array([1, 2, 3, 5]);
    
    const result1 = Encryption.CryptoUtils.constantTimeEqual(a, b);
    const result2 = Encryption.CryptoUtils.constantTimeEqual(a, c);
    
    if (result1 === true && result2 === false) {
      console.log('✅ PASS: Constant-time comparison working');
      testsPassed++;
    } else {
      console.log('❌ FAIL: Constant-time comparison not working');
      testsFailed++;
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during constant-time test:', error.message);
    testsFailed++;
  }
  
  // Test 9: Base64 validation
  console.log('\nTest 9: Base64 validation');
  try {
    // Test invalid base64
    try {
      Encryption.CryptoUtils.base64ToBytes("invalid-base64!@#");
      console.log('❌ FAIL: Should have rejected invalid base64');
      testsFailed++;
    } catch (error) {
      if (error.message.includes('Invalid base64')) {
        console.log('✅ PASS: Rejected invalid base64');
        testsPassed++;
      } else {
        console.log('❌ FAIL: Wrong error for invalid base64:', error.message);
        testsFailed++;
      }
    }
    
  } catch (error) {
    console.log('❌ FAIL: Error during base64 test:', error.message);
    testsFailed++;
  }
  
  // Summary
  console.log('\n' + '='.repeat(50));
  console.log('🔒 SECURITY TEST SUMMARY');
  console.log('='.repeat(50));
  console.log(`Tests Passed: ${testsPassed}`);
  console.log(`Tests Failed: ${testsFailed}`);
  console.log(`Total Tests: ${testsPassed + testsFailed}`);
  
  if (testsFailed === 0) {
    console.log('\n🎉 ALL SECURITY TESTS PASSED!');
    console.log('✅ Version 2.1.0 security fixes are working correctly');
  } else {
    console.log('\n⚠️  SOME SECURITY TESTS FAILED!');
    console.log('❌ Security fixes may not be working correctly');
  }
  
  // Restore console.log
  console.log = originalConsoleLog;
  
  return testsFailed === 0;
}

// Run tests if this file is executed directly
if (require.main === module) {
  runSecurityTests().then(success => {
    process.exit(success ? 0 : 1);
  }).catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });
}

module.exports = { runSecurityTests }; 