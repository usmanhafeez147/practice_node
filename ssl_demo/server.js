
const https = require("https");
const fs = require("fs");

const options = {
    key: fs.readFileSync("./certs/server.key"),
    cert: fs.readFileSync("./certs/server.crt"),
    minVersion: "TLSv1.2"
};

const server = https.createServer(options, (req, res) => {

    console.log("\nIncoming HTTPS request");

    console.log("URL:", req.url);
    console.log("Method:", req.method);
    console.log("TLS Version:", req.socket.getProtocol());

    res.writeHead(200, {
        "Content-Type": "application/json"
    });

    res.end(JSON.stringify({
        success: true,
        message: "Secure HTTPS connection established!",
        protocol: req.socket.getProtocol(),
        timestamp: new Date().toISOString()
    }));

});

server.listen(4433, () => {
    console.log("HTTPS server running!");
    console.log("https://localhost:4433");
});
