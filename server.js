// ===== Imports and Setup =====
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import cors from "cors";
import fs from "fs";
import { X509Certificate } from "crypto"; 
import * as jose from 'jose'; // <<< NEW: JOSE library for JWS/JWT signing

// ===== Configuration =====
const DOMAIN = "family-organizer.onrender.com"; // Use "family-organizer.onrender.com" for deployment
// const DOMAIN = "localhost:3000"; // Use this for local testing (ensure certs are in place)
const PORT = process.env.PORT || 3000;
const CERT_FILE_PATH = "/etc/secrets/family-organizer.pem";
const KEY_FILE_PATH = "/etc/secrets/family-organizer.key"; // User-specified Private Key path

// <<< MOVED DID AND VM ID TO GLOBAL SCOPE for use in the signing API
const DID = `did:web:${DOMAIN}`;
const VERIFICATION_METHOD_ID = `${DID}#x509`;
// >>>

// ===== Key Loading and Initialization (NEW) =====
let signingKey;
try {
    const PRIVATE_KEY_PEM = fs.readFileSync(KEY_FILE_PATH, 'utf8');
    // Asynchronously import the key for ES256 signing
    (async () => {
        try {
            // jose.importPKCS8 is used to import the PEM private key for ES256
            signingKey = await jose.importPKCS8(PRIVATE_KEY_PEM, 'ES256');
            console.log("Private Signing Key (P-256/ES256) loaded successfully.");
        } catch (err) {
            console.error("CRITICAL: Failed to load P-256 Private Key for ES256 signing:", err.message);
        }
    })();
} catch (err) {
    console.error(`CRITICAL: Failed to read key file from ${KEY_FILE_PATH}:`, err.message);
}
// ===== End Key Loading =====

// ===== Utility Function for Base64url Encoding (EXISTING) =====
function toBase64url(base64) {
    return base64.replace(/\+/g, "-")
                 .replace(/\//g, "_")
                 .replace(/=/g, "");
}

/**
 * Creates a partial JWK from a PEM-encoded P-256 Public Key by parsing the ASN.1 structure.
 * This is specific to P-256 ECDSA keys.
 */
function createJwkFromP256Pem(pubKeyPem) {
    const pemContent = pubKeyPem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/[\r\n]/g, "")
        .trim();
        
    const keyBuffer = Buffer.from(pemContent, 'base64');
    
    // P-256 SPECIFIC: The raw P-256 public key is 64 bytes.
    // In SPKI, it is typically wrapped in a sequence:
    // SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 }, BIT STRING { 04 || X || Y } }
    // We target the 64 bytes starting at offset 23 (assuming a standard SPKI structure)
    // The first byte (04) is the uncompressed point identifier and is ignored for JWK.
    const keyBytes = keyBuffer.subarray(23); 

    // Extract X and Y coordinates (32 bytes each for P-256)
    const x = toBase64url(keyBytes.subarray(1, 33).toString('base64'));
    const y = toBase64url(keyBytes.subarray(33).toString('base64'));

    return {
        kty: "EC", // Elliptic Curve
        crv: "P-256", // Curve P-256
        x: x,
        y: y
    };
}


// ===== Express App Initialization =====
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(process.cwd(), "public")));

// ===== API: ToDo List (EXISTING) =====
const todos = []; 
app.get("/api/todos", (req, res) => {
    res.json(todos);
});

app.post("/api/todos", (req, res) => {
    const { text } = req.body;
    const newTodo = { id: Date.now(), text, checked: false };
    todos.push(newTodo);
    res.status(201).json(newTodo);
});

app.put("/api/todos/:id", (req, res) => {
    const id = parseInt(req.params.id);
    const { checked } = req.body;
    const todo = todos.find(t => t.id === id);
    if (todo) {
        todo.checked = checked;
        res.json(todo);
    } else {
        res.status(404).send("Not found");
    }
});

app.delete("/api/todos/:id", (req, res) => {
    const id = parseInt(req.params.id);
    const index = todos.findIndex(t => t.id === id);
    if (index !== -1) {
        todos.splice(index, 1);
        res.status(204).send();
    } else {
        res.status(404).send("Not found");
    }
});

// ===== API: Sign VC (JWS/JWT) (NEW ROUTE) =====
app.post("/api/sign-vc", async (req, res) => {
    // 1. Check if the key was loaded successfully
    if (!signingKey) {
        console.error("Signing failed: Private key not initialized.");
        return res.status(500).send("Server initialization error: Key not available for signing.");
    }
    
    const vcPayload = req.body.vcPayload;

    if (!vcPayload || !vcPayload.issuer || !vcPayload.credentialSubject || !vcPayload.credentialSubject.id) {
        return res.status(400).send("Missing required 'vcPayload' or its 'issuer'/'credentialSubject.id' in request body.");
    }

    try {
        // Prepare JWT Claims (Payload)
        const now = Math.floor(Date.now() / 1000);
        const jwtClaims = {
            ...vcPayload, // VC payload is the core claims
            iss: vcPayload.issuer, 
            sub: vcPayload.credentialSubject.id, 
            nbf: now,
            exp: now + (365 * 24 * 60 * 60), // Expires in 1 year
            iat: now
        };

        // 2. Sign the JWT using ES256
        const signedJwt = await new jose.SignJWT(jwtClaims)
            .setProtectedHeader({ 
                alg: 'ES256', 
                typ: 'vc+jwt', 
                kid: VERIFICATION_METHOD_ID 
            })
            .setKey(signingKey)
            .sign();
            
        console.log(`Successfully signed VC with KID: ${VERIFICATION_METHOD_ID}`);
        
        // 3. Return the raw signed JWT
        res.set('Content-Type', 'application/vc+jwt').send(signedJwt);

    } catch (err) {
        console.error("VC Signing Error:", err.message);
        res.status(500).send(`Failed to sign VC: ${err.message}`);
    }
});
// ===== End API: Sign VC =====

// ===== DID Document Endpoint (EXISTING - UPDATED to use global constants) =====
app.get("/.well-known/did.json", (req, res) => {
    try {
        // Read the certificate file content
        const certFileContent = fs.readFileSync(CERT_FILE_PATH, 'utf8');
        const cert = new X509Certificate(certFileContent);
        
        // Extract public key and create a partial JWK
        const pubKeyPem = cert.publicKey.export({ type: 'spki', format: 'pem' });
        const jwkPartial = createJwkFromP256Pem(pubKeyPem);

        // Final JWK with x5t#S256
        const jwkFinal = {
            ...jwkPartial,
            kid: VERIFICATION_METHOD_ID,
            // Calculate x5t#S256 from the certificate's SHA-256 fingerprint
            "x5t#S256": toBase64url(cert.fingerprint256.replace(/:/g, '')),
        };

        const x5uUri = `https://${DOMAIN}/certs/p256.pem`;

        const didDoc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/x509-jwk-2020/v1"
            ],
            id: DID,
            verificationMethod: [
                {
                    id: VERIFICATION_METHOD_ID,
                    type: "X509Jwk2020",
                    controller: DID,
                    publicKeyJwk: jwkFinal, 
                    x5u: x5uUri 
                }
            ],
            authentication: [VERIFICATION_METHOD_ID],
            assertionMethod: [VERIFICATION_METHOD_ID]
        };

        console.log("--- DID Doc Generation Complete ---");
        
        // Respond with the generated document and the correct Content-Type header
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

// ===== Start Server =====
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Access the application at https://${DOMAIN}`);
    console.log(`DID is: ${DID}`);
    console.log(`Verification Method ID is: ${VERIFICATION_METHOD_ID}`);
});