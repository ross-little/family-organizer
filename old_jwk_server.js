// ===== Imports and Setup =====
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import cors from "cors";
import fs from "fs";
import { X509Certificate } from "crypto"; 
import * as jose from 'jose';
// import pemJwk from 'pem-jwk'; // Import the default export
import crypto from "crypto";            // for crypto.randomUUID()

// cookie parser
import cookieParser from "cookie-parser";
// session management
import session from "express-session";
// ===== Express App Initialization (EXISTING) =====
// ... (rest of express setup code)
const app = express();

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// Determine if running in production (Render) or development
// SET NODE_ENV=Development (Windows CMD) when testing locally as below:
// set NODE_ENV=development && node server.js

// or on linux: NODE_ENV=development node server.js

const IS_PROD = process.env.NODE_ENV === "production";

console.log(`Environment: ${IS_PROD ? "Production" : "Development"}`);


// ===== Configuration =====
const DOMAIN = "family-organizer.onrender.com"; 
// const DOMAIN = "localhost:3000"; 
const PORT = process.env.PORT || 3000;
// const CERT_FILE_PATH = "/etc/secrets/family-organizer.pem";
// const KEY_FILE_PATH = "/etc/secrets/family-organizer.key"; 
const DID = `did:web:${DOMAIN}`;
const VERIFICATION_METHOD_ID = `${DID}#x509-jwk-1`;  // ✅ consistent
console.log(`DID: ${DID}`);
console.log(`Verification Method ID: ${VERIFICATION_METHOD_ID}`);

// 0. TRUST PROXY: Required for Express to work behind a reverse proxy like Render
// This tells Express to trust the proxy's headers (X-Forwarded-For, X-Forwarded-Proto)
if (IS_PROD) {
    app.set('trust proxy', 1); // Trust the Render proxy
}
// 1. Cookie parser
// Session setup (keep this near the top, after cookieParser)
app.use(cookieParser());

// 2. Session setup

// Session setup
app.use(
  session({
    name: "fo_session", // custom cookie name
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false, // only save sessions when something is stored
    cookie: {
      httpOnly: true,               // JS cannot access the cookie
      secure: IS_PROD,              // HTTPS only in production
      sameSite: IS_PROD ? "none" : "lax", // cross-site cookies if needed
      maxAge: SESSION_TTL_MS         // persist 30 days
    }
  })
);

// ===== Key Loading and Initialization (UPDATED) =====
let signingKey;

function resolveSecretPath(filename) {
  // 1️⃣ Absolute path on Render/Linux
  const renderPath = path.join("/etc/secrets", filename);
  if (fs.existsSync(renderPath)) return renderPath;

  // 2️⃣ Local hidden folder for dev
  const dotEtcPath = path.join(process.cwd(), ".etc", "secrets", filename);
  if (fs.existsSync(dotEtcPath)) return dotEtcPath;

  // 3️⃣ Optional fallback inside repo
  const localPath = path.join(process.cwd(), "etc", "secrets", filename);
  if (fs.existsSync(localPath)) return localPath;

  throw new Error(`Secret file ${filename} not found in /etc/secrets, .etc/secrets, or ./etc/secrets`);
}


function loadSigningKey() {
  try {
    const keyPath = resolveSecretPath("family-organizer.key");
    const pem = fs.readFileSync(keyPath, "utf8");

    // Detect EC key (SEC1) or PKCS#8 and create crypto.KeyObject
    if (pem.includes("BEGIN EC PRIVATE KEY")) {
      signingKey = crypto.createPrivateKey({ key: pem, format: "pem", type: "sec1" });
    } else if (pem.includes("BEGIN PRIVATE KEY")) {
      signingKey = crypto.createPrivateKey({ key: pem, format: "pem", type: "pkcs8" });
    } else {
      throw new Error("Unsupported private key format");
    }

    console.log(`✅ Private key loaded successfully from: ${keyPath}`);
  } catch (err) {
    console.error("❌ CRITICAL: Failed to load Private Key:", err.message);
    process.exit(1); // Exit if key fails
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
    const y = toBase64url(keyBytes.subarray(33, 65).toString('base64'));

    return {
        kty: "EC", // Elliptic Curve
        crv: "P-256", // Curve P-256
        x: x,
        y: y
    };
}


// ===== Express App Initialization (EXISTING) =====
// ... (rest of express setup code)
// const app = express();
app.use(cors({
    origin: IS_PROD ? DOMAIN : 'http://localhost:3000', // Allow CORS from your domain
    credentials: true // Crucial for sending cookies cross-origin/with CORS
}));
app.use(bodyParser.json());

// 3. Global session/debug logger — place here, BEFORE routes
app.use((req, res, next) => { 
  console.log(`➡️ ${req.method} ${req.url}`);
  console.log("   Session data:", req.session.user);
  next();
});

// 4. Serve static files from 'public' directory
app.use(express.static(path.join(process.cwd(), "public")));



// 5. API routes (login, session/me, logout, todos, etc.)
// C. Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.isAuthenticated) {
        next();
    } else {
        // DEBUG: Log unauthorized access attempts
        console.warn(`[AUTH FAILED] Attempt to access ${req.path} without session.`);
        res.status(401).send("Unauthorized: Please log in."); 
    }
}

// ===== API: ToDo List (EXISTING) =====
// 5. API routes (login, session/me, logout, todos, etc.)


// ============= Manage login session cookie ============
// --- SESSION HANDLING --- //
// Login
app.post("/api/session/login", (req, res) => {
    const { user } = req.body;
    
    if (!user || !user.email) {
        return res.status(400).send("User data is required.");
    }
    
    // Set the session variables
    req.session.isAuthenticated = true;
    req.session.user = user;
    
    req.session.save(err => {
        if (err) {
            console.error("[SESSION ERROR] Failed to save session:", err);
            return res.status(500).send("Failed to save session.");
        }
        console.log(`[SESSION] Established for: ${user.email}`);
        res.json({ success: true, message: "Session created." });
    });
});

// 2. Endpoint to retrieve current session user
app.get("/api/session/me", isAuthenticated, (req, res) => {
    res.json(req.session.user);
    console.log("➡️ Active session:", req.session.user);
});



app.post("/api/session/logout", (req, res) => {
  console.log("➡️ Logging out user:", req.session.user);

  req.session.destroy(err => {
    if (err) {
      console.error("❌ Error destroying session:", err);
      return res.status(500).json({ error: "Failed to logout" });
    }

    // Clear cookie manually
    res.clearCookie("fo_session", {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: IS_PROD ? "none" : "lax"
    });

    res.json({ success: true });
  });
});


// ===== End Session Handling =====

const todos = []; 


// ... (rest of ToDo API endpoints)
app.get("/api/todos", isAuthenticated, (req, res) => {
    res.json(todos);
});

app.post("/api/todos", isAuthenticated, (req, res) => { // <-- FIX: Protection added
    const { text } = req.body;
    if (!text) return res.status(400).send("Text is required.");
    
    const newTodo = { 
        id: Date.now(), 
        text, 
        checked: false, 
        // owner: req.session.user.id // Assign to the logged-in user
    };
    todos.push(newTodo);
    console.log(`[TODO POST] User ${req.session.user.email} added: ${text}`); // <-- DEBUG LOG
    res.status(201).json(newTodo);
});



app.put("/api/todos/:id", isAuthenticated,(req, res) => {
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

app.delete("/api/todos/:id", isAuthenticated, (req, res) => {
    const id = parseInt(req.params.id);
    const index = todos.findIndex(t => t.id === id);
    if (index !== -1) {
        todos.splice(index, 1);
        res.status(204).send();
    } else {
        res.status(404).send("Not found");
    }
});

// ===== End ToDo List API =====

// ===== API: Sign VC (JWS/JWT) (EXISTING) =====
app.post("/api/sign-vc", async (req, res) => {
  // short wait loop for signingKey if it's still initializing
  for (let i = 0; i < 20 && !signingKey; ++i) await new Promise(r => setTimeout(r, 90));
  if (!signingKey) {
    console.error("Signing key not ready in /api/sign-vc");
    return res.status(500).send("Signing key not ready");
  }

  const vcPayload = req.body?.vcPayload;
  // Alert if vcPayload is missing for debugging
  if (!vcPayload.credentialSubject || (!vcPayload.credentialSubject.id && !vcPayload.credentialSubject['@id'])) {
    return res.status(400).send("Missing credentialSubject.id or credentialSubject.@id");
  } 

  if (!vcPayload) {
    // DEBUG: Log the received body for troubleshooting
    console.warn("No vcPayload in request body:", req.body);
    
    return res.status(400).send("Missing vcPayload");
  }

  try {
    const now = Math.floor(Date.now() / 1000);

    // issuer: prefer explicit issuer in payload, otherwise use your DID
    const issuer = vcPayload.issuer || DID; // DID global is did:web:...

    // const subject = vcPayload.credentialSubject.id;
    const subject = vcPayload.credentialSubject.id || vcPayload.credentialSubject['@id'];

    // Build the JWT claim set using the VC data model top-level fields.
    // We deep-clone incoming payload to avoid mutation.
    const claims = JSON.parse(JSON.stringify(vcPayload));

    // Remove embedded issuer (we'll put it in standard 'iss' claim to follow VC-JWT mapping)
    delete claims.issuer;

    // Ensure required JWT registered claims are present/normalized:
    // if (!claims.id && vcPayload.id) claims.id = vcPayload.id;   // keep VC id if provided
    // set standard JWT claims (do not overwrite if caller provided)
    if (!claims.iss) claims.iss = issuer;
    if (!claims.sub) claims.sub = subject;
    if (!claims.iat) claims.iat = now;
    if (!claims.nbf) claims.nbf = now;
    if (!claims.exp) claims.exp = now + (365 * 24 * 60 * 60); // default 1 year
    if (!claims.jti) claims.jti = `urn:uuid:${crypto.randomUUID()}`;

    // Protected header per VC-JWT spec (credential-claims-set mapping)
    const protectedHeader = {
      alg: "ES256",
      typ: "vc+jwt",                  // required header media-type for VC-JWT credential claimset
      cty: "vc",                      // recommended header media-type for nested VC in JWT
      iss: issuer,                    // optional, can include in header
      kid: VERIFICATION_METHOD_ID     // MUST exactly match didDoc verificationMethod id
    };

    // Sign the JWT with jose
    const signed = await new jose.SignJWT(claims)
      .setProtectedHeader(protectedHeader)
      .sign(signingKey);

    // Respond with media-type application/vc+jwt (per W3C VC-JWT IANA registration)
    res.set("Content-Type", "application/vc+jwt").status(200).send(signed);

  } catch (err) {
    console.error("Error signing VC:", err);
    res.status(500).send(`Signing error: ${err?.message || err}`);
  }
});

// ===== End API: Sign VC =====

// ===== API: Sign VP (JWS/JWT) (EXISTING) =====
// ===== API: Sign VP (JWS/JWT) =====
// ===== API: Sign VP (JWS/JWT) =====
app.post("/api/sign-vp", async (req, res) => {
    try {
        // wait for signingKey if still initializing
        for (let i = 0; i < 20 && !signingKey; ++i) await new Promise(r => setTimeout(r, 90));
        if (!signingKey) {
            console.error("Signing key not ready in /api/sign-vp");
            return res.status(500).send("Signing key not ready");
        }

        const vpPayload = req.body?.vpPayload;
        if (!vpPayload) {
            return res.status(400).send("Missing vpPayload");
        }

        // Protected header
        const protectedHeader = {
            alg: "ES256",
            typ: "vp+jwt",        // VP-JWT media type
            cty: "vp",            // nested VP media type
            iss: DID,            // issuer is your DID
            kid: VERIFICATION_METHOD_ID
        };

        // Sign the VP exactly as received
        const signedVp = await new jose.SignJWT(vpPayload)
            .setProtectedHeader(protectedHeader)
            .sign(signingKey);

        // Return signed VP-JWT
        res.set("Content-Type", "application/vp+jwt").status(200).send(signedVp);

    } catch (err) {
        console.error("[SIGN VP ERROR]", err);
        res.status(500).send(`VP signing error: ${err?.message || err}`);
    }
});



// ===== End API: Sign VP =====

// ===== DID Document Endpoint (EXISTING) =====
app.get("/.well-known/did.json", (req, res) => {
    try {
        const did = `did:web:${DOMAIN}`;
        const verificationMethodId = VERIFICATION_METHOD_ID;  // reuse global constant

        
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