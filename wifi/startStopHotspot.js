const { exec } = require("child_process");
const os = require("os");

const SSID = "MyHotspotName";
const PASSWORD = "MyPassword123"; // min 8 chars

const platform = os.platform();

function run(cmd) {
    return new Promise((resolve, reject) => {
        console.log(`\n[RUN] ${cmd}`);
        exec(cmd, (err, stdout, stderr) => {
            if (err) return reject(stderr || err.message);
            resolve(stdout);
        });
    });
}

// -----------------------------
// WINDOWS
// -----------------------------
async function startWindowsHotspot() {
    await run(`netsh wlan set hostednetwork mode=allow ssid="${SSID}" key="${PASSWORD}"`);
    await run(`netsh wlan start hostednetwork`);
    console.log("Windows hotspot started");
}

async function stopWindowsHotspot() {
    await run(`netsh wlan stop hostednetwork`);
    console.log("Windows hotspot stopped");
}

// -----------------------------
// LINUX (nmcli)
// -----------------------------
async function startLinuxHotspot() {
    await run(`nmcli dev wifi hotspot ifname wlan0 ssid "${SSID}" password "${PASSWORD}"`);
    console.log("Linux hotspot started");
}

async function stopLinuxHotspot() {
    await run(`nmcli connection down Hotspot`);
    console.log("Linux hotspot stopped");
}

// -----------------------------
// MACOS (AppleScript workaround)
// -----------------------------
async function startMacHotspot() {
    console.log("macOS does not support direct CLI hotspot creation.");

    const script = `
    tell application "System Settings"
      activate
    end tell
  `;

    await run(`osascript -e '${script}'`);

    console.log("Please enable Internet Sharing manually:");
    console.log("System Settings → General → Sharing → Internet Sharing");
}

// -----------------------------
// MAIN
// -----------------------------
async function startHotspot() {
    try {
        if (platform === "win32") {
            await startWindowsHotspot();
        } else if (platform === "linux") {
            await startLinuxHotspot();
        } else if (platform === "darwin") {
            await startMacHotspot();
        } else {
            console.log("Unsupported OS");
        }
    } catch (err) {
        console.error("Error:", err);
    }
}

// async function stopHotspot() {
//     try {
//         if (platform === "win32") {
//             await stopWindowsHotspot();
//         } else if (platform === "linux") {
//             await stopLinuxHotspot();
//         } else {
//             console.log("Stop not supported on this OS");
//         }
//     } catch (err) {
//         console.error("Error:", err);
//     }
// }

// Run
startHotspot();

// To stop:
// stopHotspot();