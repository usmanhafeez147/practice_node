const { exec } = require('child_process');
const os = require('os');

// ─── CONFIG ───────────────────────────────────────────────
const TARGET_SSID = 'YourWiFiName';    // WiFi to connect TO
const TARGET_PASSWORD = 'YourPassword';    // WiFi password
const MAX_RETRIES = 5;                 // Connection retry attempts
const RETRY_DELAY = 3000;              // Delay between retries (ms)

const HOTSPOT_PASSWORD = 'MyPassword123';   // Your hotspot password (min 8 chars)
// ──────────────────────────────────────────────────────────

const platform = os.platform();

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function runCommand(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, (err, stdout, stderr) => {
            if (err) return reject(new Error(stderr || err.message));
            resolve(stdout);
        });
    });
}

// ─── 1. START HOTSPOT ─────────────────────────────────────
async function startHotspot(ssid, password) {
    console.log(`\n📡 Starting hotspot "${ssid}"...`);
    try {
        if (platform === 'win32') {
            await runCommand(`netsh wlan set hostednetwork mode=allow ssid="${ssid}" key="${password}"`);
            await runCommand(`netsh wlan start hostednetwork`);

        } else if (platform === 'linux') {
            const ifaceRaw = await runCommand(`iw dev | awk '$1=="Interface"{print $2}' | head -1`);
            const iface = ifaceRaw.trim();
            await runCommand(`nmcli dev wifi hotspot ifname ${iface} ssid "${ssid}" password "${password}"`);

        } else if (platform === 'darwin') {
            console.log('macOS: Enable Internet Sharing manually in System Settings.');
            return;

        } else {
            throw new Error('Unsupported platform: ' + platform);
        }

        console.log(`Hotspot "${ssid}" is ON!`);
    } catch (err) {
        console.error('Hotspot failed:', err.message);
    }
}

// ─── 2. STOP HOTSPOT ──────────────────────────────────────
async function stopHotspot() {
    console.log('\nStopping hotspot...');
    try {
        if (platform === 'win32') {
            await runCommand(`netsh wlan stop hostednetwork`);
        } else if (platform === 'linux') {
            await runCommand(`nmcli con down Hotspot`);
        } else {
            console.log('macOS: Disable Internet Sharing manually.');
            return;
        }
        console.log('Hotspot stopped.');
    } catch (err) {
        console.error('Failed to stop hotspot:', err.message);
    }
}

// ─── 3. CONNECT TO WIFI WITH RETRY ────────────────────────
function tryConnect(ssid, password) {
    return new Promise((resolve, reject) => {
        let cmd;

        if (platform === 'win32') {
            cmd = `netsh wlan connect name="${ssid}"`;
        } else if (platform === 'linux') {
            cmd = `nmcli dev wifi connect "${ssid}" password "${password}"`;
        } else if (platform === 'darwin') {
            cmd = `networksetup -setairportnetwork en0 "${ssid}" "${password}"`;
        } else {
            return reject(new Error('Unsupported platform: ' + platform));
        }

        exec(cmd, (err, stdout, stderr) => {
            if (err) return reject(new Error(stderr || err.message));
            resolve(stdout);
        });
    });
}

async function connectWithRetry(ssid, password, maxRetries, delay) {
    console.log(`\n Attempting to connect to "${ssid}"...`);

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        console.log(`\nAttempt ${attempt} of ${maxRetries}...`);
        try {
            const result = await tryConnect(ssid, password);
            console.log(`Connected on attempt ${attempt}!`);
            console.log(result);
            return true;
        } catch (err) {
            console.error(`Attempt ${attempt} failed:`, err.message);
            if (attempt < maxRetries) {
                console.log(`Retrying in ${delay / 1000}s...`);
                await sleep(delay);
            } else {
                console.error(`\nAll ${maxRetries} attempts failed.`);
                return false;
            }
        }
    }
}

// ─── 4. GET CONNECTED CLIENTS ─────────────────────────────
async function getConnectedClients() {
    console.log(`\n👥 Fetching connected clients... (OS: ${platform})`);
    try {
        if (platform === 'win32') {
            const hotspot = await runCommand('netsh wlan show hostednetwork');
            console.log('Hotspot Status:\n', hotspot);
            const arp = await runCommand('arp -a');
            console.log('Connected Devices:\n', arp);

        } else if (platform === 'linux') {
            const ifaceRaw = await runCommand(`iw dev | awk '$1=="Interface"{print $2}' | head -1`);
            const iface = ifaceRaw.trim();
            console.log(`Interface: ${iface}`);
            const stations = await runCommand(`iw dev ${iface} station dump`);
            console.log('Connected Stations:\n', stations || '(none)');
            const arp = await runCommand('arp -a');
            console.log('IP/MAC Table:\n', arp);

        } else if (platform === 'darwin') {
            const info = await runCommand('airport -I');
            console.log('WiFi Info:\n', info);
            const arp = await runCommand('arp -a');
            console.log('Connected Devices:\n', arp);

        } else {
            throw new Error('Unsupported platform: ' + platform);
        }
    } catch (err) {
        console.error('Error fetching clients:', err.message);
    }
}

// ─── MAIN ─────────────────────────────────────────────────
async function main() {
    console.log('🖥️  Detected OS:', platform);

    // Step 1: Connect to a target WiFi
    await connectWithRetry(TARGET_SSID, TARGET_PASSWORD, MAX_RETRIES, RETRY_DELAY);
    
    // Step 2: Start your hotspot
    await startHotspot(TARGET_SSID, HOTSPOT_PASSWORD);


    // Step 3: Check who's connected to your hotspot
    await getConnectedClients();

    // Step 4: Stop hotspot when done (uncomment if needed)
    // await stopHotspot();
}

main();