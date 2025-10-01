// ===== Imports and Setup =====
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import cors from "cors";
import fs from "fs";
import { X509Certificate } from "crypto"; 
import * as jose from 'jose';
import { pemToJwk } from 'pem-jwk'; // <<< NEW IMPORT for key conversion



// ===== Configuration =====
const DOMAIN = "family-organizer.onrender.com"; 
// const DOMAIN = "localhost:3000"; 
const PORT = process.env.PORT || 3000;
const CERT_FILE_PATH = "/etc/secrets/family-organizer.pem";
const KEY_FILE_PATH = "/etc/secrets/family-organizer.key"; 

const DID = `did:web:${DOMAIN}`;
const VERIFICATION_METHOD_ID = `${DID}#x509`;

// ===== Key Loading and Initialization (UPDATED) =====
let signingKey;

async function loadSigningKey() {
    try {
        const PRIVATE_KEY_PEM = fs.readFileSync(KEY_FILE_PATH, 'utf8');
        
        // 1. Attempt to import the key directly as PKCS#8 (the expected format by jose)
        try {
            signingKey = await jose.importPKCS8(PRIVATE_KEY_PEM, 'ES256');
            console.log("Private Signing Key (P-256/ES256) loaded successfully using PKCS#8.");
        } catch (err) {
            // 2. If PKCS#8 import fails, it's likely a standard 'EC PRIVATE KEY' format.
            if (err.message.includes("pkcs8")) {
                console.log("PKCS#8 import failed. Attempting conversion to JWK...");
                
                // Use pemToJwk to convert the key to JWK format
                const jwk = pemToJwk(PRIVATE_KEY_PEM);
                
                // Add required ES256/P-256 parameters if missing
                if (jwk.kty !== 'EC') {
                    throw new Error("Key is not a recognizable Elliptic Curve (EC) key.");
                }
                
                // 3. Import the converted JWK
                signingKey = await jose.importJWK(jwk, 'ES256');
                console.log("Private Signing Key (P-256/ES256) loaded successfully after PEM-to-JWK conversion.");
            } else {
                // Re-throw any other unexpected error
                throw err;
            }
        }
        
    } catch (err) {
        console.error(`CRITICAL: Failed to load Private Key from ${KEY_FILE_PATH}:`, err.message);
    }
}

// Start key loading immediately
loadSigningKey(); 
// ===== End Key Loading =====


// ===== Utility Function for Base64url Encoding (EXISTING) =====
// ... (rest of toBase64url function)
function toBase64url(base64) {
    return base64.replace(/\+/g, "-")
                 .replace(/\//g, "_")
                 .replace(/=/g, "");
}

// ... (rest of createJwkFromP256Pem function)
function createJwkFromP256Pem(pubKeyPem) {
    const pemContent = pubKeyPem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/[\r\n]/g, "")
        .trim();
        
    const keyBuffer = Buffer.from(pemContent, 'base64');
    
    // P-256 SPECIFIC: The raw P-256 public key is 64 bytes.
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


// ===== Express App Initialization (EXISTING) =====
// ... (rest of express setup code)
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(process.cwd(), "public")));


// ===== API: ToDo List (EXISTING) =====
// ... (rest of ToDo API endpoints)
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


// ===== API: Sign VC (JWS/JWT) (EXISTING) =====
app.post("/api/sign-vc", async (req, res) => {
    // Check if the key was loaded successfully
    if (!signingKey) {
        // Wait briefly for key to load if it's still being loaded (async)
        await new Promise(resolve => setTimeout(resolve, 100));
        if (!signingKey) {
            console.error("Signing failed: Private key not initialized.");
            return res.status(500).send("Server initialization error: Key not available for signing.");
        }
    }
    
    const vcPayload = req.body.vcPayload;
    // ... (rest of validation)
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

        // Sign the JWT using ES256
        const signedJwt = await new jose.SignJWT(jwtClaims)
            .setProtectedHeader({ 
                alg: 'ES256', 
                typ: 'vc+jwt', 
                kid: VERIFICATION_METHOD_ID 
            })
            .setKey(signingKey)
            .sign();
            
        console.log(`Successfully signed VC with KID: ${VERIFICATION_METHOD_ID}`);
        
        // Return the raw signed JWT
        res.set('Content-Type', 'application/vc+jwt').send(signedJwt);

    } catch (err) {
        console.error("VC Signing Error:", err.message);
        res.status(500).send(`Failed to sign VC: ${err.message}`);
    }
});
// ===== End API: Sign VC =====


// ===== DID Document Endpoint (EXISTING) =====
app.get("/.well-known/did.json", (req, res) => {
    try {
        const did = `did:web:${DOMAIN}`;
        const verificationMethodId = `${did}#x509-jwk-1`;
        
        console.log("--- DID Doc Resolution Started ---");
        console.log(`[DID Resolution] Handling request for ${did} at /.well-known/did.json`);

        // --- 1. Load Leaf Certificate and Extract Public Key ---
        const leafCertPath = path.join(process.cwd(), "public", ".well-known", "cert", "0000_cert.pem");
        const leafPem = fs.readFileSync(leafCertPath).toString('utf8');
        
        const x509 = new X509Certificate(leafPem);
        const pubKeyPem = x509.publicKey.export({ type: "spki", format: "pem" });

        // --- 2. Dynamically Determine Key Parameters ---
        let jwk = {};
        
        // Use asymmetricKeyType for robust checking (avoids generic 'public' string)
        const asymmetricKeyType = x509.publicKey.asymmetricKeyType; 
        const keyDetails = x509.publicKey.asymmetricKeyDetails;

        console.log(`[Dynamic Key] Asymmetric Type: ${asymmetricKeyType}`);

        // Handle ECDSA P-256
        if (asymmetricKeyType === 'ec' && keyDetails.namedCurve === 'prime256v1') {
            
            console.log("[Dynamic Key] Confirmed: P-256 (prime256v1) for ECDSA");
            
            const jwkResult = createJwkFromP256Pem(pubKeyPem);

            // Set required JWK fields for P-256
            jwk = {
                kty: "EC",
                crv: "P-256", // Standard name for JWK/DID-JWK
                x: jwkResult.x,
                y: jwkResult.y,
                alg: "ES256", 
                use: "sig",
                _debug: jwkResult._debug 
            };
            
        } else if (asymmetricKeyType === 'rsaEncryption' || asymmetricKeyType === 'rsa') {
            // FUTURE SUPPORT: Handle RSA Key extraction here
            console.log("[Dynamic Key] Detected: RSA. JWK creation not yet implemented.");
            throw new Error("RSA Key support is not yet implemented.");
            
        } else {
            // Throw an error for truly unsupported keys
            throw new Error(`Unsupported Key Type detected: ${asymmetricKeyType}`);
        }
        
        // Remove debug property before response
        const jwkFinal = {...jwk};
        delete jwkFinal._debug;

        console.log(`[JWK Debug] Key Type: ${jwk.kty}, Algorithm: ${jwk.alg}`);
        

        // --- 3. Define x5u URI ---
        // Protocol must be explicitly included for the URI: https://<domain>
        const x5uUri = `https://${DOMAIN}/.well-known/fullpem/0001_chain.pem`;

        // --- 4. Assemble DID Document ---
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
                    publicKeyJwk: jwkFinal, 
                    x5u: x5uUri 
                }
            ],
            authentication: [verificationMethodId],
            assertionMethod: [verificationMethodId]
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