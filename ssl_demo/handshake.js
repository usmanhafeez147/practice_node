// A real TLS handshake, seen from the CLIENT (the "browser").
//
// This script is the client process. The server process is server.js, which
// must already be running (npm run server). Every value printed below is
// read from the live connection - nothing is simulated.

const tls = require("tls");
const net = require("net");
const fs = require("fs");
const path = require("path");
const { X509Certificate } = require("crypto");

// Where server.js is listening.
const HOST = "localhost";
const PORT = 4433;

// The client only needs the server's certificate, to know what to trust.
// The private key (server.key) stays with the server.
const serverCert = fs.readFileSync(path.join(__dirname, "certs", "server.crt"));

const browser = {
    name: "Chrome",
    minVersion: "TLSv1.2",
    maxVersion: "TLSv1.3",

    // Key exchange groups offered in the Client Hello, in preference order.
    keyExchangeGroups: "X25519:P-256"
};

// Step 1: Client Hello
function clientHello() {

    console.log("\n1. CLIENT HELLO");

    console.log("Browser:", browser.name);
    console.log("Connecting to:", `${HOST}:${PORT}`);
    console.log("Offered TLS versions:", `${browser.minVersion} - ${browser.maxVersion}`);
    console.log("Offered key exchange groups:", browser.keyExchangeGroups);
    console.log("Offered cipher suites:", tls.DEFAULT_CIPHERS.split(":").filter((c) => !c.startsWith("!")).length);
    console.log("Server name (SNI):", HOST);

    return new Promise((resolve, reject) => {

        // Session secrets derived during the handshake (NSS key log format).
        const secrets = [];

        // The plain TCP connection. TLS runs on top of it, so its byte
        // counters show what actually travels over the wire.
        const tcp = net.connect(PORT, HOST);

        tcp.once("error", reject);

        const socket = tls.connect({
            socket: tcp,
            servername: HOST,
            minVersion: browser.minVersion,
            maxVersion: browser.maxVersion,
            ecdhCurve: browser.keyExchangeGroups,

            // Trust our locally generated certificate.
            ca: serverCert,

            // Verify the certificate chain and hostname.
            rejectUnauthorized: true
        });

        socket.on("keylog", (line) => secrets.push(line.toString().split(" ")[0]));

        // Fires when the handshake has completed and the certificate was accepted.
        socket.once("secureConnect", () => resolve({ socket, tcp, secrets }));
        socket.once("error", reject);
    });
}

// Step 2: Server Hello
function serverHello(socket) {

    console.log("\n2. SERVER HELLO");

    const cipher = socket.getCipher();

    console.log("Selected TLS:", socket.getProtocol());
    console.log("Selected cipher suite:", cipher.standardName || cipher.name);
}

// Step 3: Certificate validation
function validateCertificate(socket) {

    console.log("\n3. CERTIFICATE VALIDATION");

    const peer = socket.getPeerCertificate();
    const certificate = new X509Certificate(peer.raw);

    console.log("Subject:", certificate.subject);
    console.log("Issuer:", certificate.issuer);
    console.log("Valid from:", certificate.validFrom);
    console.log("Valid to:", certificate.validTo);
    console.log(
        "Public key:",
        certificate.publicKey.asymmetricKeyType.toUpperCase(),
        `${peer.bits} bits`
    );
    console.log("SHA-256 fingerprint:", certificate.fingerprint256);

    // Chain of trust: did the certificate verify against our trusted CA?
    if (!socket.authorized) {
        throw new Error(`Invalid certificate: ${socket.authorizationError}`);
    }

    // Hostname: does the certificate belong to the host we asked for?
    const identityError = tls.checkServerIdentity(HOST, peer);

    if (identityError) {
        throw new Error(`Domain mismatch: ${identityError.message}`);
    }

    // Expiry: is the certificate inside its validity window?
    const now = Date.now();

    if (now < Date.parse(certificate.validFrom) || now > Date.parse(certificate.validTo)) {
        throw new Error("Certificate is expired or not yet valid!");
    }

    console.log("Certificate validation successful!");
}

// Step 4: Key exchange
function keyExchange(socket, secrets) {

    console.log("\n4. KEY EXCHANGE");

    const key = socket.getEphemeralKeyInfo();

    console.log(
        "Ephemeral key exchange:",
        key.type ? `${key.type}E ${key.name || ""} (${key.size} bits)` : "not reported by Node for this group"
    );

    console.log("Secrets derived from the shared key:");

    secrets.forEach((label) => console.log("  -", label));
}

function indent(text) {
    return text.split(/\r?\n/).map((line) => "  " + line).join("\n");
}

// Step 5: Secure communication
function secureConnection(socket, tcp) {

    console.log("\n5. SECURE CONNECTION");

    // A real HTTP request. TLS encrypts it before it leaves this process.
    const message = [
        "GET / HTTP/1.1",
        `Host: ${HOST}:${PORT}`,
        "Connection: close",
        "",
        ""
    ].join("\r\n");

    console.log("Browser sent:");
    console.log(indent(message.trim()));

    return new Promise((resolve, reject) => {

        let reply = "";

        socket.on("data", (chunk) => {
            reply += chunk;
        });

        socket.on("end", () => {
            console.log("Browser decrypted:");
            console.log(indent(reply.trim()));
            console.log(
                "Plaintext bytes - sent:", Buffer.byteLength(message),
                "| received:", Buffer.byteLength(reply)
            );
            console.log(
                "Bytes on the wire (handshake + encrypted records) - sent:", tcp.bytesWritten,
                "| received:", tcp.bytesRead
            );
            resolve();
        });

        socket.on("error", reject);

        socket.write(message);
    });
}

// Execute handshake
async function startHandshake() {

    console.log("========== TLS HANDSHAKE ==========");

    // CLIENT: connect to server.js and send the Client Hello. The SERVER's
    // half of the handshake happens in the other process while we wait here.
    const { socket, tcp, secrets } = await clientHello();

    // CLIENT: read what the SERVER chose in its Server Hello.
    serverHello(socket);

    // CLIENT: check the certificate the SERVER sent.
    validateCertificate(socket);

    // CLIENT: show the key exchange result. The SERVER derived the same
    // secrets on its side.
    keyExchange(socket, secrets);

    // CLIENT: send an encrypted HTTP request. SERVER: decrypts it, logs it
    // in its own terminal, and sends back an encrypted response.
    await secureConnection(socket, tcp);

    console.log("\n========== HANDSHAKE COMPLETE ==========");
}

startHandshake().catch((error) => {
    if (error.code === "ECONNREFUSED") {
        console.error(`\nNo server on ${HOST}:${PORT}. Start it first: npm run server`);
    } else {
        console.error("\nHandshake failed:", error.message);
    }
    process.exitCode = 1;
});
