
const https = require("https");
const fs = require("fs");

const options = {
    hostname: "localhost",
    port: 4433,
    path: "/",
    method: "GET",

    // Trust our locally generated certificate.
    ca: fs.readFileSync("./certs/server.crt"),

    // Verify the certificate and hostname.
    rejectUnauthorized: true
};

console.log("Browser: Connecting to server...");

const request = https.request(options, (response) => {

    console.log("\nBrowser: Secure connection established!");

    console.log("HTTP Status:", response.statusCode);

    console.log(
        "TLS Protocol:",
        response.socket.getProtocol()
    );

    console.log(
        "Cipher:",
        response.socket.getCipher()
    );

    console.log("\nServer Response:");

    response.on("data", (chunk) => {
        console.log(chunk.toString());
    });

});

request.on("error", (error) => {
    console.error("Connection failed:", error.message);
});

request.end();
