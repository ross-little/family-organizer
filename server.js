// ===== Imports and Setup =====
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import cors from "cors";
import fs from "fs";
import { X509Certificate } from "crypto"; 

// ===== Configuration =====
//const DOMAIN = "family-organizer.onrender.com";
const DOMAIN = "localhost:3000";
const PORT = process.env.PORT || 3000;

// ===== Utility Function for Base64url Encoding =====
function toBase64url(base64) {
    return base64.replace(/\+/g, "-")
                 .replace(/\//g, "_")
                 .replace(/=/g, "");
}

// Custom function to create JWK from a P-256 Public Key
function createJwkFromP256Pem(pubKeyPem) {
    const pemContent = pubKeyPem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/[\r\n]/g, "")
        .trim();
        
    const keyBuffer = Buffer.from(pemContent, 'base64');
    
    // For P-256 keys, the raw uncompressed public key (04 || X || Y) starts at byte 26
    const rawKeyBytes = keyBuffer.subarray(26);

    // X coordinate is the 32 bytes after the leading '04' byte
    const xBuffer = rawKeyBytes.subarray(1, 33);
    // Y coordinate is the final 32 bytes
    const yBuffer = rawKeyBytes.subarray(33, 65);

    // Encode to Base64url
    const xBase64url = toBase64url(xBuffer.toString('base64'));
    const yBase64url = toBase64url(yBuffer.toString('base64'));

    // Hex debug is included in return, but will only be logged, not used in final JWK
    const xHex = xBuffer.toString('hex');
    const yHex = yBuffer.toString('hex');

    return {
        // JWK properties
        kty: "EC",
        crv: "P-256",
        x: xBase64url,
        y: yBase64url,
        // Debug properties
        _debug: { xHex: xHex, yHex: yHex }
    };
}


// ===== Express setup and Middleware (Standard) =====
const app = express();

app.use(cors({ origin: "*", credentials: true }));
app.use(bodyParser.json());
// Ensure static files are served, which is necessary for the x5u path
app.use(express.static(path.join(process.cwd(), "public")));

// ===== Todo API (Standard - Unchanged) =====
let tasks = [];
let idCounter = 1;

app.get("/api/todos", (req, res) => res.json(tasks));
app.post("/api/todos", (req, res) => {
    const { text } = req.body;
    if (text) {
        tasks.push({ id: idCounter++, text, checked: false });
        res.sendStatus(201);
    } else {
        res.sendStatus(400);
    }
});
app.put("/api/todos/:id", (req, res) => {
    const id = parseInt(req.params.id, 10);
    const task = tasks.find(t => t.id === id);
    if (task) {
        task.checked = req.body.checked;
        res.sendStatus(200);
    } else {
        res.sendStatus(404);
    }
});
app.delete("/api/todos/:id", (req, res) => {
    const id = parseInt(req.params.id, 10);
    tasks = tasks.filter(t => t.id !== id);
    res.sendStatus(200);
});


// =========================================================
// ===== DID Resolution Endpoint: Dynamic Generation at /.well-known/did.json =====
// =========================================================
app.get("/.well-known/did.json", (req, res) => {
    try {
        const did = `did:web:${DOMAIN}`;
        const verificationMethodId = `${did}#x509-jwk-1`;
        
        console.log("--- DID Doc Resolution Started ---");
        console.log(`[DID Resolution] Handling request for ${did} at /.well-known/did.json`);

        // --- 1. Generate JWK from Leaf Certificate ---
        const leafCertPath = path.join(process.cwd(), "public", ".well-known", "cert", "0000_cert.pem");
        const leafPem = fs.readFileSync(leafCertPath).toString('utf8');
        
        const x509 = new X509Certificate(leafPem);
        const pubKeyPem = x509.publicKey.export({ type: "spki", format: "pem" });

        const jwkResult = createJwkFromP256Pem(pubKeyPem);

        // Separate JWK for final document and debug data
        const jwk = {
            kty: jwkResult.kty,
            crv: jwkResult.crv,
            x: jwkResult.x,
            y: jwkResult.y,
            // Add standard required JWK fields
            alg: "ES256", 
            use: "sig"
        };
        
        console.log(`[JWK Debug] X (Base64url): ${jwk.x}`);
        console.log(`[JWK Debug] Y (Base64url): ${jwk.y}`);
        console.log(`[JWK Debug] X (Hex):         ${jwkResult._debug.xHex}`);
        console.log(`[JWK Debug] Y (Hex):         ${jwkResult._debug.yHex}`);


        // --- 2. Define x5u URI (Pointing to the full certificate chain) ---
        // This replaces the x5c array.
        const x5uUri = `https://${DOMAIN}/.well-known/fullpem/0001_chain.pem`;
        
        // Removed unnecessary certs parsing logic (from the old x5c array setup)
        console.log(`[x5u Debug] Using x5u URI: ${x5uUri}`);


        // --- 3. Assemble DID Document ---
        const didDoc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/x509-jwk-2020/v1"
            ],
            id: did,
            verificationMethod: [
                {
                    id: verificationMethodId,
                    type: "X509Jwk2020",
                    controller: did,
                    publicKeyJwk: jwk, 
                    // Use x5u URI instead of the x5c array
                    x5u: x5uUri 
                }
            ],
            authentication: [verificationMethodId],
            assertionMethod: [verificationMethodId]
        };

        console.log("--- DID Doc Generation Complete ---");
        
        // Respond to the client with the generated document and the correct Content-Type header
        res.set('Content-Type', 'application/did+json').json(didDoc);

    } catch (err) {
        console.error("--- DID Doc Resolution Failed ---");
        console.error("[DID Doc Error] Check file contents/permissions for cert files.");
        console.error("Error Details:", err.message);
        res.status(500).json({
            error: "Could not generate DID Doc.",
            message: err.message
        });
    }
});

// ===== Serve index.html for SPA (Standard) =====
app.get("/", (req, res) => {
    res.sendFile(path.join(process.cwd(), "public", "index.html"));
});

// ===== Start server (Standard) =====
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});