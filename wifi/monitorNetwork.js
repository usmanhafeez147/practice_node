const { exec } = require('child_process');
const os = require('os');

function runCommand(cmd) {
    return new Promise((resolve, reject) => {
        exec(cmd, (err, stdout, stderr) => {
            if (err) return reject(new Error(stderr || err.message));
            resolve(stdout);
        });
    });
}

async function getConnectedClients() {
    const platform = os.platform();
    console.log(`Detected OS: ${platform}\n`);

    try {
        if (platform === 'win32') {
            // Windows
            const hotspot = await runCommand('netsh wlan show hostednetwork');
            console.log('Hotspot Status:\n', hotspot);

            const arp = await runCommand('arp -a');
            console.log('Connected Devices (ARP table):\n', arp);

        } else if (platform === 'linux') {
            // Linux — auto detect active WiFi interface
            const ifaceRaw = await runCommand(`iw dev | awk '$1=="Interface"{print $2}' | head -1`);
            const iface = ifaceRaw.trim();

            if (!iface) {
                console.error('No WiFi interface found');
                return;
            }

            console.log(`Using interface: ${iface}\n`);

            const stations = await runCommand(`iw dev ${iface} station dump`);
            console.log('Connected Stations:\n', stations || '(no clients connected)');

            const arp = await runCommand('arp -a');
            console.log('IP/MAC Table:\n', arp);

        } else if (platform === 'darwin') {
            // macOS
            const stations = await runCommand('airport -I');
            console.log('WiFi Info:\n', stations);

            const arp = await runCommand('arp -a');
            console.log('Connected Devices (ARP table):\n', arp);

        } else {
            console.error(`Unsupported platform: ${platform}`);
        }

    } catch (err) {
        console.error('Error:', err.message);
    }
}

getConnectedClients();