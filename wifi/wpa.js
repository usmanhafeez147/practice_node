const crypto = require('crypto');

// Pre-shared key (like the Wi-Fi password)
const PSK = 'supersecret';

// Simulate AP and Mobile
function derivePMK(psk) {
    // Simulate key derivation from PSK
    return crypto.createHash('sha256').update(psk).digest('hex');
}

function generateNonce() {
    return crypto.randomBytes(16).toString('hex');
}

// Derive PTK (session key)
function derivePTK(pmk, nonce1, nonce2) {
    const combined = pmk + nonce1 + nonce2;
    return crypto.createHash('sha256').update(combined).digest('hex');
}

// Simulated handshake
function wpaHandshakeSimulation() {
    console.log('\n--- WPA Handshake Simulation ---\n');

    // Step 1: Both derive PMK from PSK
    const pmkAP = derivePMK(PSK);
    const pmkMobile = derivePMK(PSK);

    console.log('PMK (AP):     ', pmkAP);
    console.log('PMK (Mobile):', pmkMobile);

    // Step 2: AP sends its nonce
    const apNonce = generateNonce();
    console.log('\nAP sends nonce:', apNonce);

    // Step 3: Mobile sends its nonce + MIC (simulated hash)
    const mobileNonce = generateNonce();
    const ptkMobile = derivePTK(pmkMobile, apNonce, mobileNonce);
    const micMobile = crypto.createHash('md5').update(ptkMobile).digest('hex');

    console.log('Mobile sends nonce:', mobileNonce);
    console.log('Mobile MIC:        ', micMobile);

    // Step 4: AP derives PTK and verifies MIC
    const ptkAP = derivePTK(pmkAP, apNonce, mobileNonce);
    const micCheck = crypto.createHash('md5').update(ptkAP).digest('hex');

    console.log('\nAP derived PTK: ', ptkAP);
    console.log('AP checks MIC:  ', micCheck);

    const isVerified = micMobile === micCheck;
    console.log('\nMIC verified:', isVerified ? 'YES - Secure!' : 'NO - Failed');

    // Final Step: Both sides can now use PTK to encrypt data
    if (isVerified) {
        console.log('\nEncrypted session ready.');
    }
}

wpaHandshakeSimulation();