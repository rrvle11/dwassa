const http = require('http');
const validator = require('validator');

// Simple test runner
function runTests() {
    console.log('🧪 Running tests...\n');
    
    // Test 1: Validator functions
    testValidatorFunctions();
    
    // Test 2: Environment variables
    testEnvironmentVariables();
    
    // Test 3: Server connectivity (if running)
    testServerConnectivity();
    
    console.log('\n✅ All tests completed!');
}

function testValidatorFunctions() {
    console.log('📝 Testing validator functions...');
    
    // Test username validation
    const validUsernames = ['user123', 'testuser', 'admin'];
    const invalidUsernames = ['us', 'user@123', 'verylongusernamethatexceedslimit'];
    
    validUsernames.forEach(username => {
        const isValid = validator.isLength(username, { min: 3, max: 20 }) && 
                       validator.isAlphanumeric(username);
        console.log(`  ✓ Username "${username}": ${isValid ? 'VALID' : 'INVALID'}`);
    });
    
    // Test email validation
    const validEmails = ['test@example.com', 'user@domain.org'];
    const invalidEmails = ['invalid-email', 'test@', '@domain.com'];
    
    validEmails.forEach(email => {
        const isValid = validator.isEmail(email);
        console.log(`  ✓ Email "${email}": ${isValid ? 'VALID' : 'INVALID'}`);
    });
    
    console.log('');
}

function testEnvironmentVariables() {
    console.log('🔧 Testing environment variables...');
    require('dotenv').config();
    
    const requiredVars = ['MONGODB_URL', 'SESSION_SECRET', 'NODE_ENV'];
    
    requiredVars.forEach(varName => {
        const value = process.env[varName];
        const exists = !!value;
        const isPlaceholder = value && (value.includes('change-this') || value.includes('your-'));
        
        console.log(`  ${exists ? '✓' : '✗'} ${varName}: ${exists ? 'SET' : 'MISSING'}${isPlaceholder ? ' (PLACEHOLDER)' : ''}`);
    });
    
    console.log('');
}

function testServerConnectivity() {
    console.log('🌐 Testing server connectivity...');
    
    const options = {
        hostname: 'localhost',
        port: 3000,
        path: '/api/pastes',
        method: 'GET',
        timeout: 2000
    };
    
    const req = http.request(options, (res) => {
        console.log(`  ✓ Server responded with status: ${res.statusCode}`);
        res.on('data', () => {}); // Consume response data
    });
    
    req.on('error', (err) => {
        console.log(`  ✗ Server connection failed: ${err.message}`);
        console.log('    (This is expected if the server is not running)');
    });
    
    req.on('timeout', () => {
        console.log('  ✗ Server connection timed out');
        req.destroy();
    });
    
    req.end();
}

// Run tests
runTests();
