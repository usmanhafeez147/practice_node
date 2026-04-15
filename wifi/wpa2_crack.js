const crypto = require('crypto');

// Fake captured MIC from handshake
const capturedMIC = '5d41402abc4b2a76b9719d911017c592'; // Example MIC (md5 of 'hello')

// Simulated handshake data
const apNonce = 'ap123';
const clientNonce = 'client456';

// Wordlist (normally thousands of guesses)
const wordlist = ['password123', 'qwerty', 'hello', 'letmein'];

function derivePMK(psk) {
    return crypto.createHash('sha256').update(psk).digest('hex');
}

function derivePTK(pmk, anonce, cnonce) {
    return crypto.createHash('sha256').update(pmk + anonce + cnonce).digest('hex');
}

function generateMIC(ptk) {
    return crypto.createHash('md5').update(ptk).digest('hex');
}

function simulateAttack() {
    console.log('Starting fake dictionary attack...\n');

    for (let pskGuess of wordlist) {
        const pmk = derivePMK(pskGuess);
        const ptk = derivePTK(pmk, apNonce, clientNonce);
        const mic = generateMIC(ptk);

        console.log(`Trying PSK: ${ pskGuess } -> MIC: ${ mic }`);

        if (mic === capturedMIC) {
            console.log(`\nMatch found! The password is: "${pskGuess}"`);
            return;
        }
    }

    console.log('\nNo match found in the dictionary.');
}

simulateAttack();