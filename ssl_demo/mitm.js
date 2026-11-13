// Man-in-the-middle test cases against a real TLS connection.
//
// Three roles:
//   SERVER   - server.js, which must already be running (npm run server)
//   VICTIM   - a normal TLS client (the "browser") that verifies certificates
//   ATTACKER - sits between them and tries a different trick in every case
//
// Every case really runs the attack over real sockets and reports what the
// TLS library actually did.
//
// How the attacker gets into the middle is tested separately, with four
// methods: DNS spoofing, ARP spoofing, an evil twin Wi-Fi network and a
// compromised router. Every attack is run once through each method.
//
// Those four methods are SIMULATED. The script keeps a small model of the
// victim's network (Wi-Fi, DNS answers, ARP cache, router) and each method
// changes one part of it. The model then decides where the victim's
// connection really lands: the real server, or the attacker's port on this
// machine. Nothing is sent to any real network, router or device.
//
// From there everything is real: real TLS servers, relays and certificates
// on localhost. TLS never looks at IP or MAC addresses, so the result does
// not depend on how the attacker got into the path.

const tls = require("tls");
const net = require("net");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

// The real server (server.js).
const HOST = "localhost";
const REAL_PORT = 4433;

const CERT_DIR = path.join(__dirname, "certs");
const ATTACKER_DIR = path.join(CERT_DIR, "attacker");

// The only certificate the victim trusts.
const realCert = fs.readFileSync(path.join(CERT_DIR, "server.crt"));

// The secret the victim sends. The attacker's goal is to read it.
const SECRET = "password=hunter2";

// TLS record types (first byte of every record on the wire).
const HANDSHAKE = 0x16;
const APPLICATION_DATA = 0x17;

// ---------------------------------------------------------------------------
// Attacker's key material
// ---------------------------------------------------------------------------

// The attacker can create any key and certificate they like - except one
// signed by a CA the victim trusts. Generated once with the openssl CLI.
function createAttackerCerts() {

    fs.mkdirSync(ATTACKER_DIR, { recursive: true });

    const file = (name) => path.join(ATTACKER_DIR, name);
    const openssl = (...args) => execFileSync("openssl", args, { stdio: "ignore" });

    const selfSigned = (name, commonName) => {
        if (fs.existsSync(file(`${name}.crt`))) return;
        openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
            "-subj", `/CN=${commonName}`,
            "-keyout", file(`${name}.key`), "-out", file(`${name}.crt`)
        );
    };

    // A self-signed certificate claiming to be "localhost".
    selfSigned("fake-localhost", HOST);

    // A certificate for the attacker's own domain.
    selfSigned("evil-domain", "evil.example");

    // The attacker's own certificate authority...
    selfSigned("rogue-ca", "Totally Legit CA");

    // ...and a "localhost" certificate signed by it.
    if (!fs.existsSync(file("rogue-leaf.crt"))) {
        openssl(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-subj", `/CN=${HOST}`,
            "-keyout", file("rogue-leaf.key"), "-out", file("rogue-leaf.csr")
        );
        openssl(
            "x509", "-req", "-days", "30",
            "-in", file("rogue-leaf.csr"),
            "-CA", file("rogue-ca.crt"), "-CAkey", file("rogue-ca.key"), "-CAcreateserial",
            "-out", file("rogue-leaf.crt")
        );
    }

    const read = (name) => fs.readFileSync(file(name));

    return {
        fakeLocalhost: { key: read("fake-localhost.key"), cert: read("fake-localhost.crt") },
        evilDomain: { key: read("evil-domain.key"), cert: read("evil-domain.crt") },
        rogueLeaf: {
            key: read("rogue-leaf.key"),
            cert: Buffer.concat([read("rogue-leaf.crt"), read("rogue-ca.crt")])
        }
    };
}

// ---------------------------------------------------------------------------
// Simulated network: how the attacker gets into the middle
// ---------------------------------------------------------------------------

// Example addresses. None of them is ever contacted; real connections go to
// ports on localhost.
const VICTIM_IP = "192.168.1.10";
const ROUTER_IP = "192.168.1.1";
const ATTACKER_IP = "192.168.1.50";
const SERVER_IP = "203.0.113.10";

// The victim's network before any attack.
function cleanNetwork() {
    return {
        // Which access point the victim joined.
        wifi: { name: "CoffeeShop_WiFi", runBy: "cafe" },

        // The answer the victim gets when it looks up the server's name.
        dns: { [HOST]: SERVER_IP },

        // The victim's ARP cache: which network card owns the router's IP.
        arp: { [ROUTER_IP]: "router's network card" },

        // Who controls the router that forwards the victim's traffic.
        router: { controlledBy: "cafe" }
    };
}

// Follow the victim's connection to HOST through the network and report
// every machine it passes through.
function tracePath(network) {

    const hops = [`victim (${VICTIM_IP})`];
    let attackerInPath = false;

    if (network.wifi.runBy === "attacker") {
        hops.push(`attacker's access point "${network.wifi.name}"`);
        attackerInPath = true;
    }

    if (network.arp[ROUTER_IP] === "attacker's network card") {
        hops.push(`attacker (${ATTACKER_IP}, answering for router ${ROUTER_IP})`);
        attackerInPath = true;
    } else if (network.router.controlledBy === "attacker") {
        hops.push(`router ${ROUTER_IP} (controlled by attacker)`);
        attackerInPath = true;
    } else {
        hops.push(`router ${ROUTER_IP}`);
    }

    const destination = network.dns[HOST];

    if (destination === ATTACKER_IP) {
        hops.push(`attacker (${ATTACKER_IP}, the address DNS gave out)`);
        attackerInPath = true;
    } else {
        hops.push(`server (${destination})`);
    }

    return { hops, attackerInPath };
}

// The four ways into the middle. Each one changes one part of the network.
const methods = [
    {
        name: "DNS spoofing",
        short: "DNS",
        how: [
            "The attacker sends the victim a false DNS answer for the server's name.",
            "The victim connects straight to the attacker's IP, still believing it is the server."
        ],
        apply: (network) => { network.dns[HOST] = ATTACKER_IP; },
        changed: (network) => `DNS answer for ${HOST}: ${SERVER_IP} -> ${network.dns[HOST]}`
    },
    {
        name: "ARP spoofing",
        short: "ARP",
        how: [
            "On the same local network, the attacker claims the router's IP belongs to their network card.",
            "The victim keeps using the real server IP, but every packet goes to the attacker first."
        ],
        apply: (network) => { network.arp[ROUTER_IP] = "attacker's network card"; },
        changed: (network) => `ARP cache, ${ROUTER_IP}: router's network card -> ${network.arp[ROUTER_IP]}`
    },
    {
        name: "Evil twin Wi-Fi",
        short: "Evil twin",
        how: [
            "The attacker runs an access point with the same name as the real one.",
            "The victim joins it, so all of their traffic flows through the attacker's device."
        ],
        apply: (network) => { network.wifi = { name: "CoffeeShop_WiFi", runBy: "attacker" }; },
        changed: (network) => `Wi-Fi "${network.wifi.name}": run by cafe -> run by ${network.wifi.runBy}`
    },
    {
        name: "Compromised router",
        short: "Router",
        how: [
            "The attacker has taken over the router the victim uses.",
            "The router can send the victim's traffic anywhere, including to the attacker."
        ],
        apply: (network) => { network.router = { controlledBy: "attacker" }; },
        changed: (network) => `Router ${ROUTER_IP}: controlled by cafe -> controlled by ${network.router.controlledBy}`
    }
];

// The network the current run uses. Set by the runner.
let network = cleanNetwork();

// The victim connects to HOST. The network decides where that lands:
// the attacker's port if the attacker is in the path, the real server if not.
function victimConnects(attackerPort, overrides) {

    const { attackerInPath } = tracePath(network);

    return victimTries(attackerInPath ? attackerPort : REAL_PORT, overrides);
}

// ---------------------------------------------------------------------------
// VICTIM
// ---------------------------------------------------------------------------

// The victim wants https://localhost:4433 and sends a login request.
//
// `port` is where the connection really lands. Passing the attacker's port
// stands in for DNS or ARP spoofing: the victim asked for the real server,
// but the network delivered the connection to the attacker instead.
function victimRequest(port, overrides = {}) {

    return new Promise((resolve, reject) => {

        const request = [
            "POST /login HTTP/1.1",
            `Host: ${HOST}:${REAL_PORT}`,
            "Content-Type: application/x-www-form-urlencoded",
            `Content-Length: ${Buffer.byteLength(SECRET)}`,
            "Connection: close",
            "",
            SECRET
        ].join("\r\n");

        let response = "";

        const socket = tls.connect({
            host: "127.0.0.1",
            port,

            // The name the victim expects the certificate to match.
            servername: HOST,

            // Trust only the real certificate, and verify it.
            ca: realCert,
            rejectUnauthorized: true,

            ...overrides
        });

        socket.setTimeout(5000, () => socket.destroy(new Error("timed out")));

        // Only reached if the handshake AND certificate checks passed.
        socket.once("secureConnect", () => socket.write(request));

        socket.on("data", (chunk) => {
            response += chunk;
        });

        socket.once("error", reject);

        socket.once("close", () => {
            if (response) {
                resolve(response);
            } else {
                reject(new Error("connection closed without a response"));
            }
        });
    });
}

// OpenSSL errors look like "id:error:code:SSL routines:function:reason:file".
// Keep only the reason.
function shortError(message) {

    const firstLine = message.split("\n")[0];
    const reason = firstLine.match(/routines:[^:]*:([^:]+)/);

    return (reason ? reason[1] : firstLine).split(";")[0];
}

// Run the victim and report what happened instead of throwing.
async function victimTries(port, overrides) {

    try {
        const response = await victimRequest(port, overrides);
        return { connected: true, status: response.split("\r\n")[0] };
    } catch (error) {
        return {
            connected: false,
            error: error.code ? `${error.code}: ${shortError(error.message)}` : shortError(error.message)
        };
    }
}

// ---------------------------------------------------------------------------
// ATTACKER tools
// ---------------------------------------------------------------------------

function listen(server) {
    return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => resolve(server.address().port));
    });
}

// Attacker tool 1: a TLS server of their own, pretending to be localhost.
// Records anything it manages to decrypt.
async function startImpostor(credentials, { forwardToRealServer = false } = {}) {

    const stolen = [];

    const server = tls.createServer(credentials, (victim) => {

        victim.on("error", () => {});
        victim.on("data", (chunk) => stolen.push(chunk));

        if (forwardToRealServer) {
            // Open the attacker's own TLS connection to the real server and
            // pass the decrypted traffic through, so the victim notices nothing.
            const upstream = tls.connect({ host: HOST, port: REAL_PORT, rejectUnauthorized: false });

            upstream.on("error", () => victim.destroy());
            victim.pipe(upstream);
            upstream.pipe(victim);
        }
    });

    server.on("tlsClientError", () => {});

    const port = await listen(server);

    return {
        port,
        stolenText: () => Buffer.concat(stolen).toString(),
        close: () => server.close()
    };
}

// Split a raw TCP stream into TLS records: 1 byte type, 2 bytes version,
// 2 bytes length, then the body.
function onEachRecord(socket, handler) {

    let buffer = Buffer.alloc(0);

    socket.on("data", (chunk) => {

        buffer = Buffer.concat([buffer, chunk]);

        while (buffer.length >= 5) {

            const length = 5 + buffer.readUInt16BE(3);

            if (buffer.length < length) break;

            handler(Buffer.from(buffer.subarray(0, length)));
            buffer = buffer.subarray(length);
        }
    });
}

// Attacker tool 2: a relay. It does not speak TLS itself; it passes the raw
// bytes between victim and real server, and can record or modify each record.
async function startRelay({ tamperFromVictim, tamperFromServer } = {}) {

    const fromVictim = [];
    const fromServer = [];

    const server = net.createServer((victim) => {

        const upstream = net.connect(REAL_PORT, HOST);

        const forward = (source, target, log, tamper) => {

            onEachRecord(source, (record) => {
                const index = log.length;
                log.push(Buffer.from(record));
                target.write(tamper ? tamper(record, index, log) : record);
            });

            source.on("end", () => target.end());
            source.on("error", () => target.destroy());
            source.on("close", () => target.destroy());
        };

        forward(victim, upstream, fromVictim, tamperFromVictim);
        forward(upstream, victim, fromServer, tamperFromServer);
    });

    const port = await listen(server);

    return { port, fromVictim, fromServer, close: () => server.close() };
}

// Find the server's key share (its ECDHE public key) inside a Server Hello
// record and flip one bit of it. Returns false if this is not a Server Hello.
function corruptServerKeyShare(record) {

    if (record[0] !== HANDSHAKE || record[5] !== 0x02) return false;

    let offset = 5 + 4;                  // record header + handshake header
    offset += 2 + 32;                    // version + server random
    offset += 1 + record[offset];        // session id
    offset += 2 + 1;                     // cipher suite + compression

    const end = offset + 2 + record.readUInt16BE(offset);
    offset += 2;

    while (offset + 4 <= end) {

        const type = record.readUInt16BE(offset);
        const length = record.readUInt16BE(offset + 2);

        if (type === 0x0033) {           // key_share extension
            record[offset + 4 + length - 1] ^= 0x01;
            return true;
        }

        offset += 4 + length;
    }

    return false;
}

// The 32 random bytes the server puts in every Server Hello.
function serverRandom(record) {
    return record.subarray(11, 43).toString("hex");
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

let attacker;      // attacker's certificates, created in main()
let recorded;      // a full session recorded in case 5, replayed in case 8

const cases = [

    {
        title: "Replay the real server's certificate",
        short: "Reuse real cert",
        show: 2,
        attack: "Attacker downloads the real certificate from the server and presents it to the victim as their own.",
        expect: "blocked",

        async run() {

            // Step 1 really works: certificates are public, anyone can fetch one.
            const stolenCert = await new Promise((resolve, reject) => {
                const socket = tls.connect({ host: HOST, port: REAL_PORT, rejectUnauthorized: false }, () => {
                    const certificate = socket.getPeerX509Certificate();
                    socket.end();
                    resolve(certificate);
                });
                socket.once("error", reject);
            });

            // Step 2: a TLS server needs the certificate AND its private key.
            // The attacker has no server.key, so they try one of their own.
            let libraryError = "none";

            try {
                tls.createSecureContext({ cert: stolenCert.toString(), key: attacker.fakeLocalhost.key });
            } catch (error) {
                libraryError = shortError(error.message);
            }

            // Step 3: even a custom TLS stack that skipped that check would
            // fail. The server must sign the handshake, and the victim checks
            // the signature with the public key inside the certificate.
            const handshakeTranscript = crypto.randomBytes(64);
            const signature = crypto.sign("sha256", handshakeTranscript, attacker.fakeLocalhost.key);
            const accepted = crypto.verify("sha256", handshakeTranscript, stolenCert.publicKey, signature);

            return {
                blocked: libraryError !== "none" && !accepted,
                result: [
                    `Got the real certificate: yes (${stolenCert.subject}) - certificates are public.`,
                    `Using it with the attacker's key: refused (${libraryError}).`,
                    `Attacker's signature checked against the certificate's public key: ${accepted ? "ACCEPTED" : "rejected"}.`
                ],
                why: "A certificate is only a public statement. To use it the server must sign the handshake with the matching private key (server.key), which the attacker does not have."
            };
        }
    },

    {
        title: "Attacker's self-signed certificate for localhost",
        short: "Self-signed cert",
        show: 0,
        attack: "Attacker makes their own certificate that says \"localhost\" and runs their own TLS server.",
        expect: "blocked",

        async run() {

            const impostor = await startImpostor(attacker.fakeLocalhost);
            const victim = await victimConnects(impostor.port);

            impostor.close();

            return {
                blocked: !victim.connected && !impostor.stolenText().includes(SECRET),
                result: [
                    `Victim: ${victim.connected ? "CONNECTED" : "aborted the handshake"} (${victim.error || victim.status}).`,
                    `Attacker read the secret: ${impostor.stolenText().includes(SECRET) ? "YES" : "no - the request was never sent"}.`
                ],
                why: "Anyone can write \"localhost\" in a certificate. It only counts if a CA the victim trusts signed it, and this one is signed by nobody the victim trusts."
            };
        }
    },

    {
        title: "Certificate signed by the attacker's own CA",
        short: "Own CA",
        show: 0,
        attack: "Attacker creates a certificate authority, signs a \"localhost\" certificate with it and sends the whole chain.",
        expect: "blocked",

        async run() {

            const impostor = await startImpostor(attacker.rogueLeaf);
            const victim = await victimConnects(impostor.port);

            impostor.close();

            return {
                blocked: !victim.connected && !impostor.stolenText().includes(SECRET),
                result: [
                    `Victim: ${victim.connected ? "CONNECTED" : "aborted the handshake"} (${victim.error || victim.status}).`,
                    `Attacker read the secret: ${impostor.stolenText().includes(SECRET) ? "YES" : "no - the request was never sent"}.`
                ],
                why: "A chain is only as good as its root. The attacker's CA is not in the victim's trusted list, so everything it signs is worthless."
            };
        }
    },

    {
        title: "A genuinely trusted certificate for another domain",
        short: "Wrong domain",
        show: 0,
        attack: "Attacker owns evil.example and has a certificate for it that the victim's trust store accepts. They present it for localhost.",
        expect: "blocked",

        async run() {

            const impostor = await startImpostor(attacker.evilDomain);

            // The victim really does trust this certificate - for evil.example.
            const victim = await victimConnects(impostor.port, { ca: [realCert, attacker.evilDomain.cert] });

            impostor.close();

            return {
                blocked: !victim.connected && !impostor.stolenText().includes(SECRET),
                result: [
                    `Victim: ${victim.connected ? "CONNECTED" : "aborted the handshake"} (${victim.error || victim.status}).`,
                    `Attacker read the secret: ${impostor.stolenText().includes(SECRET) ? "YES" : "no - the request was never sent"}.`
                ],
                why: "A trusted certificate is not enough. Its name must match the host the victim asked for, and \"evil.example\" is not \"localhost\"."
            };
        }
    },

    {
        title: "Relay everything untouched and eavesdrop",
        short: "Eavesdrop",
        show: 2,
        attack: "Attacker does not fake the server. They pass the real handshake through byte for byte and record everything.",
        expect: "blocked",

        async run() {

            const relay = await startRelay();
            const victim = await victimConnects(relay.port);

            relay.close();

            const captured = Buffer.concat([...relay.fromVictim, ...relay.fromServer]);
            const sawSecret = captured.includes(SECRET);
            const sawHttp = captured.includes("HTTP/1.1");

            // Kept for the replay attack in case 8.
            recorded = { fromVictim: relay.fromVictim, fromServer: relay.fromServer };

            return {
                blocked: victim.connected && !sawSecret && !sawHttp,
                result: [
                    `Victim: ${victim.connected ? `connected normally (${victim.status})` : `failed (${victim.error})`}.`,
                    `Attacker captured ${captured.length} bytes in ${relay.fromVictim.length + relay.fromServer.length} records.`,
                    `Secret found in the capture: ${sawSecret ? "YES" : "no"}. Any readable HTTP: ${sawHttp ? "YES" : "no"}.`,
                    `Hostname visible in the Client Hello: ${captured.includes(HOST) ? "yes" : "no"} (the one thing TLS does not hide here).`
                ],
                why: "The shared key is computed from the private halves of the key exchange, which never cross the wire. The attacker sees both public halves and still cannot derive it."
            };
        }
    },

    {
        title: "Relay, but swap the server's key exchange value",
        short: "Swap key share",
        show: 1,
        attack: "Attacker passes the real certificate and signature through, but changes the server's public key share so the victim agrees a key with them instead.",
        expect: "blocked",

        async run() {

            let tampered = false;

            const relay = await startRelay({
                tamperFromServer(record) {
                    if (!tampered && corruptServerKeyShare(record)) tampered = true;
                    return record;
                }
            });

            const victim = await victimConnects(relay.port);

            relay.close();

            return {
                blocked: tampered && !victim.connected,
                result: [
                    `Key share in the Server Hello modified: ${tampered ? "yes" : "NO"}.`,
                    `Victim: ${victim.connected ? "CONNECTED" : "aborted the handshake"} (${victim.error || victim.status}).`
                ],
                why: "Every handshake message is protected by keys derived from the key shares, and the server's signature covers them too. Change one bit and the two sides no longer agree, so the handshake dies."
            };
        }
    },

    {
        title: "Relay, but modify the encrypted request",
        short: "Modify data",
        show: 1,
        attack: "Attacker lets the handshake finish, then flips one bit in the victim's encrypted request, hoping to change it without knowing the key.",
        expect: "blocked",

        async run() {

            let tampered = false;

            const relay = await startRelay({
                tamperFromVictim(record, index, log) {

                    // The victim's first encrypted record is its Finished
                    // message; the second one is the HTTP request.
                    const encryptedSoFar = log.filter((r) => r[0] === APPLICATION_DATA).length;

                    if (record[0] === APPLICATION_DATA && encryptedSoFar === 2 && !tampered) {
                        record[record.length - 1] ^= 0x01;
                        tampered = true;
                    }

                    return record;
                }
            });

            const victim = await victimConnects(relay.port);

            relay.close();

            return {
                blocked: tampered && !victim.connected,
                result: [
                    `Encrypted request modified in transit: ${tampered ? "yes (1 bit)" : "NO"}.`,
                    `Victim: ${victim.connected ? `GOT A RESPONSE (${victim.status})` : `got no response (${victim.error})`}.`
                ],
                why: "Every record carries an authentication tag computed with the session key. The server recomputes it, sees it does not match, discards the record and kills the connection."
            };
        }
    },

    {
        title: "Replay a recorded session",
        short: "Replay",
        show: 2,
        attack: "Attacker takes the victim's bytes recorded in case 5 and sends them to the server again, hoping the login request runs a second time. Replaying needs no special position: anyone can connect to the server.",
        expect: "blocked",

        async run() {

            if (!recorded) {
                return { blocked: false, result: ["Nothing was recorded in case 5."], why: "" };
            }

            const replay = await new Promise((resolve) => {

                const records = [];
                const socket = net.connect(REAL_PORT, HOST);
                let closedByServer = false;

                onEachRecord(socket, (record) => records.push(record));

                socket.setTimeout(3000, () => socket.destroy());
                socket.on("end", () => { closedByServer = true; });
                socket.on("error", () => { closedByServer = true; });
                socket.on("close", () => resolve({ records, closedByServer }));

                socket.write(Buffer.concat(recorded.fromVictim));
            });

            const originalRandom = serverRandom(recorded.fromServer[0]);
            const replayRandom = replay.records[0] ? serverRandom(replay.records[0]) : "";

            const originalBytes = Buffer.concat(recorded.fromServer).length;
            const replayBytes = Buffer.concat(replay.records).length;

            return {
                blocked: replay.closedByServer && replayRandom !== originalRandom && replayBytes < originalBytes,
                result: [
                    `Server random, original session: ${originalRandom.slice(0, 16)}...`,
                    `Server random, replayed session: ${replayRandom.slice(0, 16)}... (${replayRandom === originalRandom ? "SAME" : "different"})`,
                    `Server ${replay.closedByServer ? "dropped the connection" : "KEPT THE CONNECTION OPEN"} after ${replayBytes} bytes (the real session got ${originalBytes}).`
                ],
                why: "The server picks fresh random values and a fresh key share for every connection, so this connection has new keys. The recorded records were encrypted with the old keys and no longer decrypt."
            };
        }
    },

    {
        title: "Strip the encryption (answer in plain HTTP)",
        short: "Strip TLS",
        show: 0,
        attack: "Attacker skips TLS entirely and answers the victim's connection with an unencrypted HTTP response.",
        expect: "blocked",

        async run() {

            let received = Buffer.alloc(0);

            const server = net.createServer((victim) => {
                victim.on("error", () => {});
                victim.on("data", (chunk) => {
                    received = Buffer.concat([received, chunk]);
                    victim.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                });
            });

            const port = await listen(server);
            const victim = await victimConnects(port);

            server.close();

            return {
                blocked: !victim.connected && !received.includes(SECRET),
                result: [
                    `Victim: ${victim.connected ? "ACCEPTED THE PLAIN RESPONSE" : "aborted"} (${victim.error || victim.status}).`,
                    `Attacker read the secret: ${received.includes(SECRET) ? "YES" : "no - the request was never sent"}.`
                ],
                why: "The victim asked for https, so it expects a TLS Server Hello. Anything else is a protocol error, and the request is only sent after a successful handshake."
            };
        }
    },

    {
        title: "Victim has certificate verification switched off",
        short: "No verification",
        show: 1,
        attack: "Attacker uses the self-signed certificate from case 2 and forwards traffic to the real server. The victim runs with rejectUnauthorized: false.",
        expect: "succeeds",

        async run() {

            const impostor = await startImpostor(attacker.fakeLocalhost, { forwardToRealServer: true });
            const victim = await victimConnects(impostor.port, { rejectUnauthorized: false });

            impostor.close();

            const stolen = impostor.stolenText().includes(SECRET);

            return {
                blocked: !stolen,
                result: [
                    `Victim: ${victim.connected ? `connected and noticed nothing (${victim.status})` : `failed (${victim.error})`}.`,
                    `Attacker read the secret: ${stolen ? `YES -> "${SECRET}"` : "no"}.`
                ],
                why: "The encryption worked perfectly - with the attacker. TLS only stops a man in the middle if the client checks who it is talking to. This is the only case that changes the victim, and the only one that works."
            };
        }
    },

    {
        title: "No attacker: real client and real server",
        short: "Real flow",
        show: 0,
        attack: "None. The victim connects straight to server.js.",
        expect: "connects",

        async run() {

            const victim = await victimConnects(null);

            return {
                connected: victim.connected,
                result: [
                    `Victim: ${victim.connected ? `connected (${victim.status})` : `FAILED (${victim.error})`}.`
                ],
                why: "The server holds server.key, so it can sign the handshake. The certificate is in the victim's trusted list and its name matches \"localhost\". All three checks pass."
            };
        }
    }
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

function serverIsRunning() {
    return new Promise((resolve) => {
        const socket = net.connect(REAL_PORT, HOST);
        socket.once("connect", () => { socket.destroy(); resolve(true); });
        socket.once("error", () => resolve(false));
    });
}

function verdict(testCase, outcome) {

    if (testCase.expect === "connects") {
        return outcome.connected
            ? { label: "SECURE CONNECTION ESTABLISHED", asExpected: true }
            : { label: "CONNECTION FAILED", asExpected: false };
    }

    const label = outcome.blocked ? "ATTACK BLOCKED" : "ATTACK SUCCEEDED";
    const asExpected = outcome.blocked === (testCase.expect === "blocked");

    return { label, asExpected };
}

function printCaseDetail(number, testCase, outcome) {

    console.log(`\nCASE ${number}: ${testCase.title}`);
    console.log(`  Attack:   ${testCase.attack}`);
    outcome.result.forEach((line, i) => console.log(`  ${i === 0 ? "Result:   " : "          "}${line}`));
    if (outcome.why) console.log(`  Why:      ${outcome.why}`);
}

async function runCase(testCase) {
    try {
        return await testCase.run();
    } catch (error) {
        return { blocked: false, connected: false, result: [`Test crashed: ${error.message}`], why: "" };
    }
}

async function main() {

    const verbose = process.argv.includes("--verbose");

    console.log("========== MITM TEST CASES ==========");

    if (!(await serverIsRunning())) {
        console.error(`\nNo server on ${HOST}:${REAL_PORT}. Start it first: npm run server`);
        process.exitCode = 1;
        return;
    }

    attacker = createAttackerCerts();

    const attacks = cases.filter((testCase) => testCase.expect !== "connects");
    const realFlow = cases.find((testCase) => testCase.expect === "connects");

    // results[attackIndex][methodIndex] = { label, asExpected }
    const results = attacks.map(() => []);
    let unexpected = 0;

    console.log("\nThe network before any attack:");
    console.log(`  Path: ${tracePath(cleanNetwork()).hops.join(" -> ")}`);

    for (const [m, method] of methods.entries()) {

        network = cleanNetwork();
        method.apply(network);

        console.log(`\n========== METHOD ${m + 1}: ${method.name.toUpperCase()} ==========`);
        method.how.forEach((line) => console.log(`  ${line}`));
        console.log(`  Changed: ${method.changed(network)}`);
        console.log(`  Path:    ${tracePath(network).hops.join(" -> ")}`);

        // Show the full explanation once, the first time each attack runs.
        const detailed = verbose || m === 0;

        for (const [a, testCase] of attacks.entries()) {

            const outcome = await runCase(testCase);
            const { label, asExpected } = verdict(testCase, outcome);
            const flag = asExpected ? "" : "  <-- NOT what was expected";

            if (!asExpected) unexpected++;
            results[a][m] = { label, asExpected };

            if (detailed) {
                printCaseDetail(a + 1, testCase, outcome);
                console.log(`  Verdict:  ${label}${flag}`);
            } else {
                console.log(`\n  ${String(a + 1).padStart(2)}. ${label.padEnd(17)} ${testCase.title}${flag}`);
                console.log(`      ${outcome.result[testCase.show] || outcome.result[0]}`);
            }
        }
    }

    // The real flow: no method applied, nobody in the path.
    network = cleanNetwork();

    console.log("\n========== NO ATTACKER ==========");
    console.log(`  Path: ${tracePath(network).hops.join(" -> ")}`);

    const realOutcome = await runCase(realFlow);
    const real = verdict(realFlow, realOutcome);

    if (!real.asExpected) unexpected++;

    printCaseDetail(cases.length, realFlow, realOutcome);
    console.log(`  Verdict:  ${real.label}${real.asExpected ? "" : "  <-- NOT what was expected"}`);

    // Summary: every attack x every method.
    console.log("\n========== SUMMARY ==========\n");

    const nameWidth = Math.max(...attacks.map((t) => t.short.length)) + 7;
    const columnWidth = Math.max(12, ...methods.map((x) => x.short.length + 2));
    const cell = (text) => text.padEnd(columnWidth);

    console.log("".padEnd(nameWidth) + methods.map((x) => cell(x.short)).join(""));

    attacks.forEach((testCase, a) => {
        const row = results[a].map((r) => cell((r.label === "ATTACK BLOCKED" ? "blocked" : "SUCCEEDED") + (r.asExpected ? "" : "!")));
        console.log(`${String(a + 1).padStart(2)}. ${testCase.short}`.padEnd(nameWidth) + row.join(""));
    });

    console.log(`\n${cases.length}. ${realFlow.short}: ${real.label}`);

    const total = attacks.length * methods.length + 1;

    console.log(
        unexpected === 0
            ? `\nAll ${total} runs behaved as expected. Only "No verification" succeeds, through every method.`
            : `\n${unexpected} of ${total} runs did NOT behave as expected (marked with !).`
    );

    if (unexpected > 0) process.exitCode = 1;
}

main();
