// ===== Imports and Setup =====
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const { X509Certificate } = require('crypto');
const jose = require('jose');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();

// Your existing code here...
// ===== Configuration =====
const DOMAIN = "family-organizer.onrender.com"; 
const swaggerOptions = {
    swaggerDefinition: {
        openapi: "3.0.0",
        info: {
            title: "API Documentation",
            version: "1.0.0",
            description: "API for managing Verifiable Credentials",
        },
        servers: [
            {
                url: process.env.NODE_ENV === "production" ? `https://${DOMAIN}` : "http://localhost:3000", // Use your actual domain
            },
        ],
    },
    apis: ["server.cjs"], // Path to the API docs
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);

// Add these new lines to the top of the file, after the imports:
// ===== SSE In-Memory Store =====
// Maps nonce -> { code: '...', status: 'AUTHENTICATED' }
const sseEventStore = new Map();
// Maps nonce -> Response object (for long polling / SSE)
const sseClients = new Map();
// ===== NEW Compliance VC Store =====
// Maps vcId (URI/URL of the VC) -> Compliance VC JWT (string)
const VcStore = new Map();

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// Determine if running in production (Render) or development
// SET NODE_ENV=Development (Windows CMD) when testing locally as below:
// set NODE_ENV=development && node server.js

// or on linux: NODE_ENV=development node server.js

const IS_PROD = process.env.NODE_ENV === "production";

console.log(`Environment: ${IS_PROD ? "Production" : "Development"}`);



// const DOMAIN = "localhost:3000"; 
const PORT = process.env.PORT || 3000;
// const CERT_FILE_PATH = "/etc/secrets/family-organizer.pem";
// const KEY_FILE_PATH = "/etc/secrets/family-organizer.key"; 

// ------>>>> Define APP_BASE_URL based on environment
const APP_BASE_URL = process.env.NODE_ENV === "development"
    ? `http://localhost:${PORT}` // Use localhost for development
    : "https://" + DOMAIN;  // Use domain for production
console.warn(`===============>>>>>>>>>>>>>>>>>>>>>>App Base URL: ${APP_BASE_URL}`);

// ===== CORS Configuration for Development and Production =====
app.use(cors({
    origin: '*', // Allows all origins
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
}));

// Swagger UI setup
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

let DID = `did:web:${DOMAIN}`;  // ✅ consistent
let tcHashHex = ""; // Global variable to store T&C hash

const kid = `x509-jwk-1`;  // fragment only
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
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors()); // <--- SOLUCIÓN: Habilitar CORS para todas las solicitudes


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



/**
 * Converts a Date object to an RFC3339 string (ISO 8601 with local offset).
 * This is often required for VC/DID timestamps (xsd:dateTime).
 * Example: 2024-01-01T10:30:00+02:00
 * * @param {Date} date - The Date object to format.
 * @returns {string} The formatted timestamp string.
 */
function toRfc3339WithLocalOffset(date) {
    const pad = (n) => (n < 10 ? '0' : '') + n;
    
    // Get date and time parts
    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hours = pad(date.getHours());
    const minutes = pad(date.getMinutes());
    const seconds = pad(date.getSeconds());

    // Get time zone offset
    const offset = date.getTimezoneOffset(); // in minutes
    const absOffset = Math.abs(offset);
    const offsetSign = offset > 0 ? '-' : '+';
    const offsetHours = pad(Math.floor(absOffset / 60));
    const offsetMinutes = pad(absOffset % 60);

    // Combine into RFC3339 format
    return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}${offsetSign}${offsetHours}:${offsetMinutes}`;
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
    // show key on startup for debugging (remove in production) on the screen
    
    const jwk = signingKey.export({ format: "jwk" });
    // console.log("✅ Private key JWK:", JSON.stringify(jwk, null, 2));

    // console.log (`✅ Private key: ${signingKey}`);
    // Print key type on user screen for debugging
    console.log (`✅ Key type: ${signingKey.asymmetricKeyType}`); 
    console.log(`✅ Private key loaded successfully ************`);
  } catch (err) {
    console.error("❌ CRITICAL: Failed to load Private Key:", err.message);
    process.exit(1); // Exit if key fails
  }

   // check_key_pair_match(PRIVATE_KEY_PATH, CERTIFICATE_PATH);
}


// Start key loading immediately
loadSigningKey(); 
// ===== End Key Loading =====

// Key Pair Verification Script (Node.js)
// This script checks if a private key matches a public certificate locally.
// It does NOT send your private key anywhere.

// Requires Node.js v18+ for crypto.X509Certificate

// const fs = require("fs");
// const crypto = require("crypto");
// const path = require("path");

// ----------------------

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
// TEST function to check key pair match

function checkKeyPairMatch() {
    const privateKeyPath = resolveSecretPath("family-organizer.key");
    const certificatePath = path.join(process.cwd(), "public", ".well-known", "cert", "0000_cert.pem");

  console.log(`\n🔐 Checking Key Pair Match`);
  console.log(`Private Key Path: ${privateKeyPath}`);
  console.log(`Certificate Path: ${certificatePath}`);

  try {
    // 1. Load Private Key
    const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");
    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      format: "pem",
      type: privateKeyPem.includes("BEGIN EC PRIVATE KEY") ? "sec1" : "pkcs8"
    });

    // 2. Derive Public Key from Private Key
    const derivedPublicKey = crypto.createPublicKey(privateKey);

    // 3. Load Certificate
    const certPem = fs.readFileSync(certificatePath, "utf8");
    const cert = new crypto.X509Certificate(certPem);

    // 4. Get Public Key from Certificate
    const certPublicKey = cert.publicKey;

    // 5. Compare Public Keys (SPKI format)
    const derivedSpki = derivedPublicKey.export({ format: "pem", type: "spki" });
    const certSpki = certPublicKey.export({ format: "pem", type: "spki" });

    const jwkFromCert = createJwkFromP256Pem(certSpki);
    console.log(" 🔑🔑🔑🔑🔑🔑🔑 [Phase I] PEM PublicKey Object:");
    console.log("Public Key JWK from Certificate:", JSON.stringify(jwkFromCert, null, 2));

    if (derivedSpki === certSpki) {
      console.log("✅ SUCCESS: The Private Key and Certificate Public Key MATCH.");
      return true;
    } else {
      console.log("❌ FAILURE: The Private Key and Certificate Public Key DO NOT MATCH.");
      return false;
    }

  } catch (err) {
    console.error("❌ ERROR:", err.message);
    return false;
  }
}

async function verifyVpJwt(vpJwt, issuerDid, VERIFICATION_METHOD_ID) {

    if (!vpJwt) {
    throw new Error("Missing vpJwt in request body");
    }
    const parts = vpJwt.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");
    const [headerB64, payloadB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
    const kid = VERIFICATION_METHOD_ID;
    if (!issuerDid || !kid) throw new Error("Missing 'iss' or 'kid'");

    const didUrl = `https://${issuerDid.split(":")[2]}/.well-known/did.json`;
    const didResp = await fetch(didUrl);
    if (!didResp.ok) throw new Error(`Failed to fetch DID document: ${didResp.status}`);
    const didDoc = await didResp.json();
    const verificationMethod = didDoc.verificationMethod?.find(vm => vm.id === kid);
    if (!verificationMethod) throw new Error("Verification method not found in DID document");
    const jwk = verificationMethod.publicKeyJwk;
    if (!jwk) throw new Error("JWK not found in verification method");

    const publicKey = await jose.importJWK(jwk, "ES256");
    const { payload: verifiedPayload } = await jose.jwtVerify(vpJwt, publicKey, {
        algorithms: ["ES256"]
    });
    console.log("Public Key FROM THE did used for verification:", publicKey);
    console.log("✅ VP JWT verified successfully.");
    return verifiedPayload;
}

async function testSignAndVerify() {
  console.log("\n🧪 ************ Running startup test: sign and verify VC");

  const payload = {
    sub: "did:web:family-organizer.onrender.com#test",
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    vc: { type: ["VerifiableCredential"], credentialSubject: { id: DID } }
  };

  const protectedHeader = {
    alg: "ES256",
    typ: "vc+jwt",
    kid: VERIFICATION_METHOD_ID
  };

  const signedJwt = await new jose.SignJWT(payload)
      .setProtectedHeader(protectedHeader)
      .sign(signingKey);
  try {

    console.log("✅ Signed JWT:", signedJwt);

    // Load public key from certificate
    const certPath = path.join(process.cwd(), "public", ".well-known", "cert", "0000_cert.pem");
    const certPem = fs.readFileSync(certPath, "utf8");
    console.log("✅ Loaded certificate for verification.");
    console.log(certPem.substring(0, 1000) + "..."); // print first 1000 chars
    const cert = new X509Certificate(certPem);
    const publicKey = cert.publicKey;
    console.log("✅ Loaded public key from certificate for verification.");
    // console.log(`Public Key Type: ${publicKey.asymmetricKeyType}`);
    // console.log(`Public Key: ${publicKey.export({ format: "pem", type: "spki" })}`);
    console.log("🔑 [Phase II]  JWK object (from pem:", JSON.stringify(createJwkFromP256Pem(publicKey.export({ format: "pem", type: "spki" })), null, 2));
    
    // console.log("************** Public Key read from the PEM:", publicKey);
    
    console.log("🔑 [Phase I] PEM PublicKey Object:", publicKey);
    console.log("🔑 [Phase I] PEM DER (raw buffer):", publicKey.export({ format: "der", type: "spki" }).toString("base64url"));

    // Verify the JWT
    const { payload: verifiedPayload } = await jose.jwtVerify(signedJwt, publicKey, {
      algorithms: ["ES256"]
    });

    console.log("✅ Verified payload:", verifiedPayload);
    console.log("🟢 Startup test passed: VC signed and verified successfully.");
  } catch (err) {
    console.error("❌ Startup test failed:", err.message);
  }

//////////////////// TEST AND VERIFY WITH DID DOC ////////////////////////
  try {
    console.log("\n🔍 part ii ----> Starting VP JWT verification FROM THE did...");
    const parts = signedJwt.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    const [headerB64, payloadB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));

    console.log("Header:", header);
    console.log("Payload:", payload);

    const issuerDid = DID;
    const kid = VERIFICATION_METHOD_ID;
 

    console.log(`Issuer DID: ${issuerDid}`);
    console.log(`Key ID (kid): ${kid}`);

    const didUrl = `https://${issuerDid.split(":")[2]}/.well-known/did.json`;
    const didResp = await fetch(didUrl);
    if (!didResp.ok) throw new Error(`Failed to fetch DID document: ${didResp.status}`);
    const didDoc = await didResp.json();

    const verificationMethod = didDoc.verificationMethod?.find(vm => vm.id === kid);
    if (!verificationMethod) throw new Error("Verification method not found in DID document");

    const jwkRaw = verificationMethod.publicKeyJwk;
    if (!jwkRaw) throw new Error("JWK not found in verification method");

    console.log("JWK:", jwkRaw);
    console.log("DID Doc:", didDoc);
    // CHECK BEFORE IMPORTING THE JWK INTO A KEY OBJECT
    console.log("🔑 [Phase II] JWK raw object (pre-import):", JSON.stringify(jwkRaw, null, 2));
    // console.log("🔑 [Phase II] Re-encoded SPKI from JWK:", Buffer.from(await jose.exportSPKI(await jose.importJWK({
    //  kty: jwk.kty,
    //  crv: jwk.crv,
    //  x: jwk.x,
    //  y: jwk.y,
    //  alg: jwk.alg
    //  }, "ES256"))).toString("base64url"));
    // FINISH JWK CHECK

    // Clean JWK before import
    const jwk = JSON.parse(JSON.stringify(jwkRaw)); // full deep clone


    const cleanJwk = {kty:String(jwk.kty),crv:String(jwk.crv),x:String(jwk.x),y:String(jwk.y)};
    // Log the cleaned JWK
    // const cleanJwk2 = {kty:"EC",crv:"P-256",x:"tGzplS5hHV2l9NuzV1yBOVmnMvML27dhXl-Jz9fxtyE",y:"zVS7ym4W72O_tW-0X_VxpBwGBtaNJFZzHrckrEPMmME"}
    // const cleanJwk2 = {kty:"EC",crv:"P-256",x:"qaMoA0kPb8-DN9CYYz_jPB_XHzJsE6F_4XkFvUMsC0E",y:"KXp-PcklzRj_3Hw62-4gEl9CMehNPmFO0BDt9ywaCbA"}

    console.log("🔑 [Phase II.1] Clean JWK object (pre-import):", JSON.stringify(cleanJwk, null, 2));
    // const publicKey = await jose.importJWK(cleanJwk, "ES256");
    const publicKeyJWK = await jose.importJWK(cleanJwk, "ES256");
    console.log("🔑 [Phase II.2] PublicKey JWK Object from importJWK:", publicKeyJWK);
    const publicKeyPEM = await jose.exportSPKI(publicKeyJWK);
    const publicKeyObject = crypto.createPublicKey(publicKeyPEM);

    // const publicKey = await jose.importJWK(jwk, "ES256");
    console.log("Public keyc:", publicKeyObject);
    console.log("🔑 [Phase II] DID PublicKey Object:", publicKeyObject);
    console.log("🔑 [Phase II] DID DER (raw buffer):", publicKeyObject.export({ format: "der", type: "spki" }).toString("base64url"));


        // Verify the JWT
    const { payload: verifiedPayload2 } = await jose.jwtVerify(signedJwt, publicKeyObject, {
      algorithms: ["ES256"]
    });

    console.log("✅ Verified payload:", verifiedPayload2);

  } catch (err) {
    console.error("❌ VC JWT verification failed:", err.message);

  }

}


// Run the start-up checks
checkKeyPairMatch();
testSignAndVerify();




// ===== Utility Function for Base64url Encoding (EXISTING) =====
// ... (rest of toBase64url function)
function toBase64url(base64) {
    return base64.replace(/\+/g, "-")
                 .replace(/\//g, "_")
                 .replace(/=/g, "");
}

// ... (rest of createJwkFromP256Pem function)

function createJwkFromP256Pem(pem) {
  // Convert PEM to raw DER bytes
  const pemBody = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const der = Buffer.from(pemBody, "base64");

  // Decode ASN.1 structure to get EC point
  // The uncompressed EC point starts with 0x04 followed by X(32) + Y(32)
  // Find 0x04 (uncompressed point marker)
  const idx = der.indexOf(0x04);
  if (idx === -1) throw new Error("Invalid EC public key: no uncompressed point found");

  const x = der.slice(idx + 1, idx + 33);
  const y = der.slice(idx + 33, idx + 65);

  if (x.length !== 32 || y.length !== 32) {
    throw new Error(`Invalid coordinate length (x=${x.length}, y=${y.length})`);
  }

  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: x.toString("base64url"),
    y: y.toString("base64url"),
    alg: "ES256",
  };

  return jwk;
}

// ===== Express App Initialization (EXISTING) =====
// ... (rest of express setup code)
// const app = express();
app.use(cors({
    origin: IS_PROD ? DOMAIN : '*', // Allow CORS from your domain
    // origin: IS_PROD ? DOMAIN : 'http://localhost:3000', // Allow CORS from your domain
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



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////// START OF UPDATES TO PROVIDE GAIA-X COMPLIANCE VC IN THE BACKEND //////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// ==========================================================
// ===== New Core Function: Sign VC Business Logic ======
// ==========================================================
/**
 * Core function to sign a Verifiable Credential payload.
 * Separated from the HTTP handler for local reusability.
 * * @param {object} vcPayload - The VC payload object (CredentialSubject MUST be present).
 * @returns {Promise<string>} The signed VC as a JWT string.
 * @throws {Error} If the signing key is not ready or the payload is invalid.
 */
export async function signVcCore(vcPayload) {
    // 1. Wait for signingKey readiness (moved here for encapsulation)
    for (let i = 0; i < 20 && !signingKey; ++i) await new Promise(r => setTimeout(r, 90));
    if (!signingKey) {
        const errorMsg = "Signing key not ready in signVcCore";
        console.error(errorMsg);
        throw new Error(errorMsg);
    }

    // 2. Validation Concern: Check for payload and required subject ID
    if (!vcPayload) {
        throw new Error("Missing vcPayload in core function call.");
    }
    
    // Check for credentialSubject.id or credentialSubject.@id
    if (!vcPayload.credentialSubject || (!vcPayload.credentialSubject.id && !vcPayload.credentialSubject['@id'])) {
        throw new Error("VC payload missing credentialSubject.id or credentialSubject.@id.");
    } 

    // 3. Call the core utility function (Assuming signVerifiableCredential is defined elsewhere)
    const signed = await signVerifiableCredential(
        vcPayload,
        signingKey,
        vcPayload.issuer,
        VERIFICATION_METHOD_ID,
        jose
    );

    return signed;
}

// ====================================================================================
// 1. CORE UTILITY FUNCTION: Encapsulates all VC Signing Logic
// ===
/**
 * Signs a Verifiable Credential payload using JWS/JWT mapping rules.
 * * @param {object} vcPayload - The VC payload (claims) to be signed.
 * @param {object} signingKey - The jose key object used for signing (e.g., an ES256 private key).
 * @param {string} DID - The Issuer's DID (e.g., did:web:...).
 * @param {string} VERIFICATION_METHOD_ID - The Key ID (kid) that corresponds to a verification method.
 * @param {object} jose - The jose library instance (e.g., from 'jose').
 * @returns {Promise<string>} The signed VC in VC-JWT format.
 */

// NOT USED DIRECTLY ANYMORE - MOVED TO signVcCore
// NOT USED DIRECTLY ANYMORE - MOVED TO signVcCore
// NOT USED DIRECTLY ANYMORE - MOVED TO signVcCore
async function signVerifiableCredential(vcPayload, signingKey, DIDparam, VERIFICATION_METHOD_ID, jose) {
    // Re-check for critical signing components (although the route handles most of this)
    if (!signingKey || !DIDparam || !VERIFICATION_METHOD_ID) {
        throw new Error("Internal signing configuration is incomplete.");
    }
    
    // --- Logic extracted from the original route handler ---
    
    const now = Math.floor(Date.now() / 1000);

    // issuer: prefer explicit issuer in payload, otherwise use your DID
    const issuer = vcPayload.issuer || DIDparam;

    // subject: The original code determined the subject here for the (commented out) 'sub' claim.
    // We'll keep the subject derivation even if 'sub' isn't explicitly set in claims.
    const subject = vcPayload.credentialSubject.id || vcPayload.credentialSubject['@id'];
    
    // Build the JWT claim set using the VC data model top-level fields.
    // Deep-clone incoming payload to avoid mutation.
    const claims = JSON.parse(JSON.stringify(vcPayload));

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

    return signed;
}

// ====================================================================================
// 2. CORE UTILITY FUNCTION: Encapsulates all VP Signing Logic
// ====================================================================================

/**
 * Signs a Verifiable Presentation payload using JWS/JWT mapping rules.
 * @param {object} vpPayload - The VP payload to be signed.
 * @param {object} signingKey - The jose key object used for signing (e.g., an ES256 private key).
 * @param {string} DIDparam - The Issuer/Holder's DID (e.g., did:web:...).
 * @param {string} VERIFICATION_METHOD_ID - The Key ID (kid) that corresponds to a verification method.
 * @param {object} jose - The jose library instance (e.g., from 'jose').
 * @returns {Promise<string>} The signed VP in VP-JWT format.
 */
async function signVerifiablePresentation(vpPayload, signingKey, DIDparam, VERIFICATION_METHOD_ID, jose) {
    // Re-check for critical signing components
    if (!signingKey || !DIDparam || !VERIFICATION_METHOD_ID) {
        throw new Error("Internal signing configuration is incomplete.");
    }
    
    // --- Logic extracted from the original route handler ---

    // Protected header per VP-JWT spec
    const protectedHeader = {
        alg: "ES256",
        typ: "vp+jwt",          // VP-JWT media type
        cty: "vp",              // nested VP media type
        iss: DIDparam,          // issuer is your DID
        kid: VERIFICATION_METHOD_ID
    };

    try {
        // Sign the VP exactly as received
        const signedVp = await new jose.SignJWT(vpPayload)
            .setProtectedHeader(protectedHeader)
            .sign(signingKey);

        // Log signed VP for debugging
        console.log("✅ Signed VP JWT:", signedVp);
        
        return signedVp;
    } catch (err) {
        // Error handling: log the error and throw a clearer error message
        console.error("Error signing VP JWT:", err);
        throw new Error(`VP signing failed: ${err.message || "Unknown error"}`);
    }
}


// ====================================================================================
// CORE UTILITY FUNCTION:  VC Storage Logic
// ====================================================================================

/**
 * Stores a  Verifiable Credential JWT using its ID as the key.
 * @param {string} vcId - The ID of the VC (used as the key).
 * @param {string} VcJwt - The full JWS/JWT of the  VC.
 * @param {Map<string, string>} VcStore - The storage mechanism (Map or equivalent).
 * @throws {Error} If input validation fails.
 */
function storeVc(vcId, VcJwt, VcStore) {
    // 1. Input validation (Moved from Express route)
    if (!vcId || typeof vcId !== 'string' || !VcJwt || typeof VcJwt !== 'string') {
        throw new Error("Invalid or missing vcId or VcJwt.");
    }

    // 2. Store the JWT using the VC ID as the key
    VcStore.set(vcId, VcJwt);

    // 3. Log (Optional, but useful to keep in the core function)
    console.log(`[VC STORE]  VC stored successfully for ID: ${vcId}`);
    console.log(`[VC STORE] Total stored VCs: ${VcStore.size}`);
}

// ====================================================================================
// CORE UTILITY FUNCTION:  VC Storage Logic
// ====================================================================================

// Collect VC JWT strings from the store (handles Map, plain object, array)
function getVcJwtsFromStore(store) {
if (!store) return [];

const out = [];

// Map (e.g., new Map())
if (store instanceof Map) {
for (const [, value] of store.entries()) {
if (typeof value === "string") out.push(value);
else if (value && typeof value.jwt === "string") out.push(value.jwt);
else if (value && typeof value.signedVc === "string") out.push(value.signedVc);
}
return out;
}

// Plain object { vcId: jwt | { jwt } }
if (typeof store === "object" && !Array.isArray(store)) {
for (const key of Object.keys(store)) {
const value = store[key];
if (typeof value === "string") out.push(value);
else if (value && typeof value.jwt === "string") out.push(value.jwt);
else if (value && typeof value.signedVc === "string") out.push(value.signedVc);
}
return out;
}

// Array [ jwt | { jwt } | { signedVc } ]
if (Array.isArray(store)) {
for (const item of store) {
if (typeof item === "string") out.push(item);
else if (item && typeof item.jwt === "string") out.push(item.jwt);
else if (item && typeof item.signedVc === "string") out.push(item.signedVc);
}
return out;
}

return out;
}

function buildVpPayloadFromStore(holderDid) {
const now = new Date();
const validFrom = toRfc3339WithLocalOffset(now);
const validUntil = toRfc3339WithLocalOffset(new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90)); // +90d

// get all JWTs
const vcJwtArray = getVcJwtsFromStore(VcStore); // VcStore from your environment

const verifiableCredential = vcJwtArray.map(jwt => ({
"@context": "https://www.w3.org/ns/credentials/v2",
"id": `data:application/vc+jwt,${jwt}`,
"type": "EnvelopedVerifiableCredential"
}));

const vpPayload = {
"@context": [
"https://www.w3.org/ns/credentials/v2",
"https://www.w3.org/ns/credentials/examples/v2"
],
"type": "VerifiablePresentation",
"verifiableCredential": verifiableCredential,
"issuer": holderDid,
"validFrom": validFrom,
"validUntil": validUntil
};

console.warn("Debug VP Payload:\n" + JSON.stringify(vpPayload, null, 2));
return vpPayload;
}



// ====================================================================================
// CORE UTILITY FUNCTION:  GET GAIA-X Compliance label VC
// ====================================================================================

function decodeJwt(jwt) {
    const base64Url = jwt.split(".")[1] || "";
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    try {
        const jsonPayload = decodeURIComponent(
            atob(base64)
                .split("")
                .map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
                .join("")
        );
        return JSON.parse(jsonPayload);
    } catch (e) {
        console.error("Failed to decode JWT:", e);
        return {};
    }
}




// ===== GAIA-X VC Operations (Self-Issue T&C VC) =====
async function selfIssueTermsAndConditionsVc(participantDid) {
    let hashHex = "";
    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);

    try {
        if (!participantDid) throw new Error("Participant DID is required.");

        const termsUrl = `${APP_BASE_URL}/.well-known/gaia-x/tc/tc.txt`;
        const termsResponse = await fetch(termsUrl);
        if (!termsResponse.ok) throw new Error(`Failed to fetch Terms & Conditions from ${termsUrl}`);
        const termsText = await termsResponse.text();

        // Compute SHA-512 hash
        const encoder = new TextEncoder();
        const data = encoder.encode(termsText);
        const hashBuffer = await crypto.subtle.digest("SHA-512", data);
        hashHex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
        tcHashHex = hashHex; // Save for later use in Legal Participant VC
        console.log("[GAIA-X] T&C SHA-512 Hash:", hashHex);

        // const vcId = `${APP_BASE_URL}/credentials/${crypto.randomUUID()}`;
       const vcId = `${APP_BASE_URL}/credentials/terms-and-conditions`;

        console.log("[GAIA-X] T&C VC ID:", vcId);

        // Create VC payload
        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            type: ["VerifiableCredential", "gx:TermsAndConditions"],
            "@id": vcId,
            "issuer":participantDid,
            "validFrom": validFrom,
            "validUntil": validUntil,
            credentialSubject: {
                "@id": `${participantDid}#TermsAndConditions`,
                "gx:hash": hashHex,
                "gx:url": { "@value": termsUrl, "@type": "xsd:anyURI" }
            }
        };
        // Add alert to show the vcPayload
        console.warn("Here is the debug T&C VC Payload:\n" + JSON.stringify(vcPayload, null, 2));

        // Sign VC
        const signedVc = await signVcCore(vcPayload);
        console.log("✅ Self-issued T&C VC JWT:", signedVc);
        // Store VC
        storeVc(vcId, signedVc, VcStore);

        return signedVc;

    } catch (error) {
        console.warn("T&C VC self-issue failed:", error);
    } finally {
        console.warn("GAIA-X T&C VC self-issue process completed.");
    }
}

// ===== GAIA-X VC Operations (Self-Issue Legal Participant VC) =====
async function selfIssueLegalParticipantVc(subjectDid, hqCountryCode, legalCountry) {

    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);
    const globalRegId = subjectDid; // Using DID as global registration ID

    try {

        if (!subjectDid || !hqCountryCode || !legalCountry) throw new Error("Missing required registration data.");

        //const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        const vcId = `${APP_BASE_URL}/credentials/legalPerson`;
        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            "@id":vcId,
            "type":["VerifiableCredential", "gx:LegalPerson"],
            "issuer":subjectDid,
            "validFrom":validFrom,
            "credentialSubject":{
                "@id": `${subjectDid}#LegalPerson`,
                "gx:legalAddress":{
                    "@type":"gx:Address",
                    "gx:countryCode":legalCountry
                    // optional: "gx:street": "...", "gx:locality": "..."
                    },
                "gx:registrationNumber":{
                    "@id":globalRegId,
                    },
                "gx:headquartersAddress":{
                    "@type":"gx:Address",
                    "gx:countryCode":hqCountryCode
                    }
                },
            "validUntil":validUntil
            };
        console.log("[GAIA-X] Legal Person VC Payload:", JSON.stringify(vcPayload, null, 2));  

        // Sign VC
        const signedVc = await signVcCore(vcPayload);
        console.log("✅ Self-issued Legal Person VC JWT:", signedVc);
        // Store VC
        storeVc(vcId, signedVc, VcStore);

        return signedVc;

    } catch (error) {
        console.warn("Self-issued Legal Person failed:", error);
    } finally {
        console.warn("GAIA-X Self-issued Legal Person process completed.");
    }
}

// ===== GAIA-X VC Operations (Self-Issue Data Consumer Participant VC) =====
async function selfIssueDataConsumerVc(subjectDid, hqCountryCode, legalCountry) {

    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);
    const globalRegId = subjectDid; // Using DID as global registration ID

    try {

        if (!subjectDid || !hqCountryCode || !legalCountry) throw new Error("Missing required issuing data.");

        //const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        const vcId = `${APP_BASE_URL}/credentials/dataConsumer`;
        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            "@id":vcId,
            "type":["VerifiableCredential", "gx:DataConsumer"],
            "issuer":subjectDid,
            "validFrom":validFrom,
            "credentialSubject":{
                "@id": `${subjectDid}#DataConsumer`,
                "gx:legalAddress":{
                    "@type":"gx:Address",
                    "gx:countryCode":legalCountry
                    // optional: "gx:street": "...", "gx:locality": "..."
                    },
                "gx:registrationNumber":{
                    "@id":globalRegId,
                    },
                "gx:headquartersAddress":{
                    "@type":"gx:Address",
                    "gx:countryCode":hqCountryCode
                    }  
                },
            "validUntil":validUntil
        };
        console.log("[GAIA-X] Data Consumer VC Payload:", JSON.stringify(vcPayload, null, 2));  

        // Sign VC
        const signedVc = await signVcCore(vcPayload);
        console.log("✅ Self-issued Data Consumer VC JWT:", signedVc);
        // Store VC
        storeVc(vcId, signedVc, VcStore);

        return signedVc;

    } catch (error) {
        console.warn("Self-issued Data Consumer failed:", error);
    } finally {
        console.warn("GAIA-X Self-issued data Consumer process completed.");
    }
}

// ===== GAIA-X VC Operations (Self-Issue Data Consumer Participant VC) =====
async function selfIssueIssuerVc(subjectDid) {

    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);

    try {

        if (!subjectDid) throw new Error("Missing required issuing data.");

        //const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        const vcId = `${APP_BASE_URL}/credentials/issuer`;
        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            "@id": vcId,
            // Per your request, setting type to 'gx:Issuer'
            "type": ["VerifiableCredential", "gx:Issuer"], 
            "issuer": subjectDid,
            "validFrom": validFrom,
            "validUntil": validUntil,
            "credentialSubject": {
                // The subject is the entity that is the Issuer
                "@id": `${subjectDid}#Issuer`,
                "gx:gaiaxTermsAndConditions": "4bd7554097444c960292b4726c2efa1373485e8a5565d94d41195214c5e0ceb3"
                // ********** Note: The gx:gaiaxTermsAndConditions value is hardcoded as per obtained from the SHACL for development:
                // https://registry.lab.gaia-x.eu/development/docs#/Trusted-Shape-registry/TrustedShapeRegistry_getShape 
            }
        };
        console.log("[GAIA-X] Issuer VC Payload:", JSON.stringify(vcPayload, null, 2));  

        // Sign VC
        const signedVc = await signVcCore(vcPayload);
        console.log("✅ Self-issued Issuer VC JWT:", signedVc);
        // Store VC
        storeVc(vcId, signedVc, VcStore);

        return signedVc;

    } catch (error) {
        console.warn("Self-issued Data Consumer failed:", error);
    } finally {
        console.warn("GAIA-X Self-issued data Consumer process completed.");
    }
}

async function requestComplianceLabelVc(subjectDid) {
    if (!subjectDid) {
        console.error("Missing DID for Compliance VC creation.");
        return;
    }

    const complianceUrlDirect = "https://compliance.lab.gaia-x.eu/development/api/credential-offers/standard-compliance";
    //let vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
    let vcId = `${APP_BASE_URL}/credentials/gaia-x-compliance-jwt`;
    
    // --- DATE FORMAT FIX ---
    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);

    // Construct VP payload
    const vpPayload = buildVpPayloadFromStore(subjectDid) ;
    try {
        
        // 1️⃣ Sign VP via local signing endpoint
        console.log("\n🔍 ----> Starting VP signing process...");
        const signResponse = await signVerifiablePresentation(vpPayload, signingKey, subjectDid, VERIFICATION_METHOD_ID, jose)
        // log the response
    
        if (!signResponse) {
            throw new Error(`VP signing failed: ${signResponse}`);
        }
        let rawVp = await signResponse;
        

        // OPTIONAL TESTING: Allow user to choose to use a test VP instead of the signed one
        // Add button to give option to continue or to use a test rawVp
        // TestVp = confirm("Do you want to use a test VP instead of the signed one?");   
        // if (TestVp) {
        //    alert("Using test VP for demonstration purposes.");
        //    console.warn("⚠️ Using test VP instead of the generated one (TestVp=true)");
        //    vcId = "https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203";
        //    rawVp = "eyJhbGciOiJFUzI1NiIsInR5cCI6InZwK2p3dCIsImN0eSI6InZwIiwiaXNzIjoiZGlkOndlYjpnYWlhLXguZXUiLCJraWQiOiJkaWQ6d2ViOmdhaWEteC5ldSNrZXktMCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwidHlwZSI6IlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkUVUxVnVhWFJmTnpnaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlIxQlRWVzVwZENKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16WTJLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UjFCVFZXNXBkRjgzT0NOamN5SXNJbWQ0T25ObFkyOXVaSE1pT2pVMkxDSm5lRHB0YVc1MWRHVnpJam8wT0N3aVozZzZaR1ZuY21WbGN5STZORFlzSW1kNE9tUmxZMmx0WVd4eklqcDdJa0IyWVd4MVpTSTZNQzQ0T0N3aVFIUjVjR1VpT2lKNGMyUTZabXh2WVhRaWZYMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTJOaXN3TVRvd01DSjkuSmhrQjlHWGx5VkhBdV9ibmkzcHNRcGY1a2xDVkNZVmlTZjR2Sm5uMmVhWDMtZHFDTVcxaW85aVZOejZtdzM1eEJKVTJ1UENzcU9iTEEtX2hoblJVclEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rZFFVMHh2WTJGMGFXOXVYelUwTXlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwSFVGTk1iMk5oZEdsdmJpSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNelk0S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlIxQlRURzlqWVhScGIyNWZOVFF6STJOeklpd2laM2c2YkdGMGFYUjFaR1VpT25zaVFHbGtJam9pWlhnNlIxQlRWVzVwZEY4M09DTmpjeUo5TENKbmVEcGhiSFJwZEhWa1pTSTZJa3B0UzBaTGEydGFJaXdpWjNnNlkzSnpJam9pUTFKVElpd2laM2c2Ykc5dVoybDBkV1JsSWpwN0lrQnBaQ0k2SW1WNE9rZFFVMVZ1YVhSZk56Z2pZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNMk9Dc3dNVG93TUNKOS5mS2VVM3Q3TWhUQV9DVDJhSy1OdS1yYVlXdUZwdzRsWUJRd0JpaV9xbFc1UzhwOGd5MjVsVHNBajNKemRQcnJ1U3lRUndZNnVOb2FTanJVaUNWRDJtUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaUlzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBNWldkaGJGQmxjbk52YmlKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16WTRLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SWl3aVozZzZiR1ZuWVd4QlpHUnlaWE56SWpwN0lrQnBaQ0k2SW1WNE9rRmtaSEpsYzNOZk9Ua3lJMk56SW4wc0ltZDRPbk4xWWs5eVoyRnVhWE5oZEdsdmJrOW1JanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHB5WldkcGMzUnlZWFJwYjI1T2RXMWlaWElpT25zaVFHbGtJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbTl5Wnk5emRXSnFaV04wY3k4eE1qTWlmU3dpWjNnNmFHVmhaSEYxWVhKMFpYSnpRV1JrY21WemN5STZleUpBYVdRaU9pSmxlRHBCWkdSeVpYTnpYems1TWlOamN5SjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNelk0S3pBeE9qQXdJbjAuNnFNTmZyWVdIM2pQdFd4QkxsdXlEaVQyQ2NPTzNUWjlzTkpVdGU2VzYzcWxPd041Q0hJaEVKYlcyNmFodlhaNzNQNkZ3ZVItYlhkMmZPSThpdWp0cnciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rRmpZMlZ6YzBOdmJuUnliMnhOWVc1aFoyVnRaVzUwWHpnNU5TSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEJZMk5sYzNORGIyNTBjbTlzVFdGdVlXZGxiV1Z1ZENKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16WTRLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UVdOalpYTnpRMjl1ZEhKdmJFMWhibUZuWlcxbGJuUmZPRGsxSTJOeklpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHB0YVcxbFZIbHdaWE1pT2lKaGNIQnNhV05oZEdsdmJpOTJibVF1YUhOc0lpd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lTMUlpTENKbmVEcDFjbXdpT25zaVFIWmhiSFZsSWpvaWFYQm1jem92TDIxNVEwbEVJaXdpUUhSNWNHVWlPaUo0YzJRNllXNTVWVkpKSW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek5qZ3JNREU2TURBaWZRLk9iMXdCN3dIazhTVnhKbFRyNWZjMEhhb1F4QnRPUWJzejRKWTJaNW5lbDlfaW5FSU9LR0FrWDVlTjZETUdqTmwxWmw2dU90TG1mYWdydDhXZmRUTmJ3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa0Z6YzJWMGMwMWhibUZuWlcxbGJuUmZNakl5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tGemMyVjBjMDFoYm1GblpXMWxiblFpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNMk9Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa0Z6YzJWMGMwMWhibUZuWlcxbGJuUmZNakl5STJOeklpd2laM2c2ZFhKc0lqcDdJa0IyWVd4MVpTSTZJbWx3Wm5NNkx5OXRlVU5KUkNJc0lrQjBlWEJsSWpvaWVITmtPbUZ1ZVZWU1NTSjlMQ0puZURwdGFXMWxWSGx3WlhNaU9pSmhjSEJzYVdOaGRHbHZiaTkyYm1RdVpYUnphUzVwY0hSMmNISnZabWxzWlN0NGJXd2lMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpLVFNJc0ltZDRPbWx1ZG05c2RtVmtVR0Z5ZEdsbGN5STZleUpBYVdRaU9pSmxlRHBNWldkaGJGQmxjbk52Ymw4M01USWpZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNMk9Tc3dNVG93TUNKOS5VTkxma0pRWHVyeXl4Y2UtTkt4MU93SHJDUWh1ZlJWbXJjdGxYSVhCWnU4R1UyeDNWeWlXdXlwRG1TbUxiZHBtc2FkNklGVTNzdERwNUdKSThZZjBpZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tKMWMybHVaWE56UTI5dWRHbHVkV2wwZVUxbFlYTjFjbVZ6WHpZME5pSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcENkWE5wYm1WemMwTnZiblJwYm5WcGRIbE5aV0Z6ZFhKbGN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNelk1S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlFuVnphVzVsYzNORGIyNTBhVzUxYVhSNVRXVmhjM1Z5WlhOZk5qUTJJMk56SWl3aVozZzZiV2x0WlZSNWNHVnpJam9pYlhWc2RHbHdZWEowTDNndGJXbDRaV1F0Y21Wd2JHRmpaU0lzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pUlZNaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOamtyTURFNk1EQWlmUS5JdEc5UE1SWUZVMmd2a19PUTI2TklkOHg5V1hEUXRzQTI3ZmE0SFRBMl82TzRmSHNsUER5VVBvdkZid19QWVVNQi11TkJQSFBFRld5QnJvVDh1WGhVZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOb1lXNW5aVUZ1WkVOdmJtWnBaM1Z5WVhScGIyNU5ZVzVoWjJWdFpXNTBYelUyTWlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRGFHRnVaMlZCYm1SRGIyNW1hV2QxY21GMGFXOXVUV0Z1WVdkbGJXVnVkQ0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpZNUt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZRMmhoYm1kbFFXNWtRMjl1Wm1sbmRYSmhkR2x2YmsxaGJtRm5aVzFsYm5SZk5UWXlJMk56SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBwYm5admJIWmxaRkJoY25ScFpYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbTFwYldWVWVYQmxjeUk2SW1Gd2NHeHBZMkYwYVc5dUwzWnVaQzVsY0hKcGJuUnpMbVJoZEdFcmVHMXNJaXdpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pVlZvaWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16WTVLekF4T2pBd0luMC4zRkhIWXBtcnVkbGpvRzVxWV90dWt3QlBEUXpxdk44OG14WklxQWtpQ1FzSUtOWXlzdi1tUURZam9qZ2VvNmlYSmNSVVVFeTYwRkNuc2ctNWxXMThZQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOdmJYQnNhV0Z1WTJWQmMzTjFjbUZ1WTJWZk9UYzJJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPa052YlhCc2FXRnVZMlZCYzNOMWNtRnVZMlVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Dc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa052YlhCc2FXRnVZMlZCYzNOMWNtRnVZMlZmT1RjMkkyTnpJaXdpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pVFZVaUxDSm5lRHBwYm5admJIWmxaRkJoY25ScFpYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPblZ5YkNJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkbTVrTG0xekxXbHRjeUo5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpBck1ERTZNREFpZlEuUGJoWXY2enBnMnFtZVUzNHhnd0VzY09NQ25XNlloYjhXQTRIZ0pBNm9OSVlTVlE0dUJwOEZRZzQ3dWprUlRyRWdnNnZreVJ3NXFaUzk4bTJoZGk1NnciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rTnZjSGx5YVdkb2RFRnVaRWx1ZEdWc2JHVmpkSFZoYkZCeWIzQmxjblI1Ukc5amRXMWxiblJmTlRVeklpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rTnZjSGx5YVdkb2RFRnVaRWx1ZEdWc2JHVmpkSFZoYkZCeWIzQmxjblI1Ukc5amRXMWxiblFpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Dc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa052Y0hseWFXZG9kRUZ1WkVsdWRHVnNiR1ZqZEhWaGJGQnliM0JsY25SNVJHOWpkVzFsYm5SZk5UVXpJMk56SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSlNVeUlzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDNadVpDNXZjR1Z1ZUcxc1ptOXliV0YwY3kxdlptWnBZMlZrYjJOMWJXVnVkQzV3Y21WelpXNTBZWFJwYjI1dGJDNXpiR2xrWlN0NGJXd2lMQ0puZURwcGJuWnZiSFpsWkZCaGNuUnBaWE1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hRWlhKemIyNWZOekV5STJOekluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOekFyTURFNk1EQWlmUS5ET1J4YjlISTh1T2xPR1ljd0Y5ejFlbHpSQXZoemFXeU0yRWlQNWNoRS1maE5mUVJvOEEzMThteUoyWWN5b0VhNGsxTkxhR1YxZzZfQVhrT3JiMUpkQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOMWMzUnZiV1Z5UVhWa2FYUnBibWRTYVdkb2RITmZORFV5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tOMWMzUnZiV1Z5UVhWa2FYUnBibWRTYVdkb2RITWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTUNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVFYVmthWFJwYm1kU2FXZG9kSE5mTkRVeUkyTnpJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5TENKbmVEcHRhVzFsVkhsd1pYTWlPaUpoY0hCc2FXTmhkR2x2Ymk5MmJtUXViM0JsYm5odGJHWnZjbTFoZEhNdGIyWm1hV05sWkc5amRXMWxiblF1Y0hKbGMyVnVkR0YwYVc5dWJXd3VjMnhwWkdWVmNHUmhkR1ZKYm1adkszaHRiQ0lzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pUTBraWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3dLekF4T2pBd0luMC53d2E4OHdEVUZScDNmUEJudk5QREpFMy1DaGZNNlhVdnM2VHUyaGZDZFp6MlctdF9ia0N5TVVCaTZxcmtJc2dqM0xxQ0RkWlhlemwwMTlhcmtmRGxVUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOMWMzUnZiV1Z5UkdGMFlVRmpZMlZ6YzFSbGNtMXpYemt3TXlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRGRYTjBiMjFsY2tSaGRHRkJZMk5sYzNOVVpYSnRjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjd0t6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZRM1Z6ZEc5dFpYSkVZWFJoUVdOalpYTnpWR1Z5YlhOZk9UQXpJMk56SWl3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMbVoxYW1sbWFXeHRMbVppTG1SdlkzVjNiM0pyY3lJc0ltZDRPblZ5YkNJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lUVUVpTENKbmVEcHBiblp2YkhabFpGQmhjblJwWlhNaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4UVpYSnpiMjVmTnpFeUkyTnpJbjE5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpBck1ERTZNREFpZlEua1dZVWdVSGlVUVlqdnZrNnBhYVJSc2VOMnFqZWw0Y0duWk90aVlnRkhQT3VOdlZLREVTWG1aOVhRWUNZUVZtU3NfakdjUkV5bW11aWRkWTMwUk9qNFEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVJHRjBZVkJ5YjJObGMzTnBibWRVWlhKdGMxODFNekFpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UTNWemRHOXRaWEpFWVhSaFVISnZZMlZ6YzJsdVoxUmxjbTF6SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56QXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBEZFhOMGIyMWxja1JoZEdGUWNtOWpaWE56YVc1blZHVnliWE5mTlRNd0kyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwdGFXMWxWSGx3WlhNaU9pSmhjSEJzYVdOaGRHbHZiaTkyYm1RdVkzSjVjSFJ2YldGMGIzSXVkbUYxYkhRaUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkNUeUlzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01Dc3dNVG93TUNKOS5qOGl5ZlJSdlZQeWhhRHRZSDN3ckt0R2tzZDBjUmpCb2k0azJIZVdCcm5ZRWVfbW9wODlnWFo2Nm5lcFlQX0J3aXNvakhzQzBqcXlJRjFMUEtkY1pQdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRlFjbTkwWldOMGFXOXVVbVZuZFd4aGRHbHZiazFsWVhOMWNtVnpYekV4TUNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRVlYUmhVSEp2ZEdWamRHbHZibEpsWjNWc1lYUnBiMjVOWldGemRYSmxjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjd0t6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSR0YwWVZCeWIzUmxZM1JwYjI1U1pXZDFiR0YwYVc5dVRXVmhjM1Z5WlhOZk1URXdJMk56SWl3aVozZzZhVzUyYjJ4MlpXUlFZWEowYVdWeklqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcG5iM1psY201cGJtZE1ZWGREYjNWdWRISnBaWE1pT2lKRFZ5SXNJbWQ0T25WeWJDSTZleUpBZG1Gc2RXVWlPaUpwY0daek9pOHZiWGxEU1VRaUxDSkFkSGx3WlNJNkluaHpaRHBoYm5sVlVra2lmU3dpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2YldWeVoyVXRjR0YwWTJncmFuTnZiaUo5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpBck1ERTZNREFpZlEuZmE3Rmx3VVVwbU82dWFPMVo2QUxmY3VkWU5QSUJNcHRpNDR1V3FJd1hTWWtQb2VtT2pnSXJQNVNZcDBpZEJxQW15NEkyemFxNzJXczhpTlZ1YTNlbUEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rUmxkbVZzYjNCdFpXNTBRM2xqYkdWVFpXTjFjbWwwZVY4Mk5URWlMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZSR1YyWld4dmNHMWxiblJEZVdOc1pWTmxZM1Z5YVhSNUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOekFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwRVpYWmxiRzl3YldWdWRFTjVZMnhsVTJWamRYSnBkSGxmTmpVeEkyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwMWNtd2lPbnNpUUhaaGJIVmxJam9pYVhCbWN6b3ZMMjE1UTBsRUlpd2lRSFI1Y0dVaU9pSjRjMlE2WVc1NVZWSkpJbjBzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDNCbmNDMXphV2R1WVhSMWNtVWlMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpUV2lKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLnAwNXJuVnN3OW5SMGw2VGJDOXFEUnQzd09JMXdMWU84VGFzM0N4ZXc1VDJjMVhOdDJPZElkMnBHNTZhdTFtZFlHOGkxcmNkX2tBNmRUNHAxNFZHVDlnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1J2WTNWdFpXNTBRMmhoYm1kbFVISnZZMlZrZFhKbGMxODBNVGtpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2Ukc5amRXMWxiblJEYUdGdVoyVlFjbTlqWldSMWNtVnpJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpFck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcEViMk4xYldWdWRFTm9ZVzVuWlZCeWIyTmxaSFZ5WlhOZk5ERTVJMk56SWl3aVozZzZaMjkyWlhKdWFXNW5UR0YzUTI5MWJuUnlhV1Z6SWpvaVUwMGlMQ0puZURwMWNtd2lPbnNpUUhaaGJIVmxJam9pYVhCbWN6b3ZMMjE1UTBsRUlpd2lRSFI1Y0dVaU9pSjRjMlE2WVc1NVZWSkpJbjBzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNmJXbHRaVlI1Y0dWeklqb2lhVzFoWjJVdmRtNWtMbVp6ZENKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLndsbVhBX2pIVnJsbmtzUER3R3hoT3lMUng3ekNOUE9PakY4NnRBM1ZZZjZoa2UtNERaTnlWZi1DMzA5d2lEaEF3ek9sQ2JjcHRJSU9INFUtTmt1Qjd3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1Z0Y0d4dmVXVmxVbVZ6Y0c5dWMybGlhV3hwZEdsbGMxODBOeUlzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBGYlhCc2IzbGxaVkpsYzNCdmJuTnBZbWxzYVhScFpYTWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTVNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rVnRjR3h2ZVdWbFVtVnpjRzl1YzJsaWFXeHBkR2xsYzE4ME55TmpjeUlzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDJaaGMzUnpiMkZ3SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkxVaUlzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmWDBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTVNzd01Ub3dNQ0o5LlRaSXFMd2xJckRFNGsta2k3SlVRbWExajdvVFV3aW9sbVgxTHdXWndXMjBMVlc2bDVSelI0c0lrbU03aHA5dDRvdlVsYnVmWUcyY2Yxa21zQnowRktBIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1Z1ZG1seWIyNXRaVzUwWVd4SmJYQmhZM1JTWlhCdmNuUmZOemMxSWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tWdWRtbHliMjV0Wlc1MFlXeEpiWEJoWTNSU1pYQnZjblFpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa1Z1ZG1seWIyNXRaVzUwWVd4SmJYQmhZM1JTWlhCdmNuUmZOemMxSTJOeklpd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkbTVrTG1OdmJXMXZibk53WVdObElpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkNUU0lzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01Tc3dNVG93TUNKOS5NRm1wa3ZScmZzX1J6OFNtX0dzOFdYNzBJc2JkbFV4b1lWNUFiMWpTTEVlOFVLZElMS0RwdFlDU25INkxPY0lJMFd1b1dFcEdkdHJFZVV2Y0hiazlVUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkdmRtVnlibTFsYm5SSmJuWmxjM1JwWjJGMGFXOXVUV0Z1WVdkbGJXVnVkRjgyTVRraUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlIyOTJaWEp1YldWdWRFbHVkbVZ6ZEdsbllYUnBiMjVOWVc1aFoyVnRaVzUwSWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56RXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBIYjNabGNtNXRaVzUwU1c1MlpYTjBhV2RoZEdsdmJrMWhibUZuWlcxbGJuUmZOakU1STJOeklpd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lUbFVpTENKbmVEcDFjbXdpT25zaVFIWmhiSFZsSWpvaWFYQm1jem92TDIxNVEwbEVJaXdpUUhSNWNHVWlPaUo0YzJRNllXNTVWVkpKSW4wc0ltZDRPbTFwYldWVWVYQmxjeUk2SW1Gd2NHeHBZMkYwYVc5dUwzWnVaQzVuYjI5bmJHVXRaV0Z5ZEdndWEyMTZJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNemN4S3pBeE9qQXdJbjAudU9XWUp4VXZLeVgwUlQ1eV9pUzdpVWpVVmViTng0ZHhGT3VQOHNDY3UzLWM4dk5neDc4NDJOM0dJLUN6bFRlZ3gzYXRCdUVIcGwzMmRWeFZ5dHJub3ciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rbHVabTl5YldGMGFXOXVVMlZqZFhKcGRIbFBjbWRoYm1sNllYUnBiMjVmTmpVM0lpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rbHVabTl5YldGMGFXOXVVMlZqZFhKcGRIbFBjbWRoYm1sNllYUnBiMjRpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa2x1Wm05eWJXRjBhVzl1VTJWamRYSnBkSGxQY21kaGJtbDZZWFJwYjI1Zk5qVTNJMk56SWl3aVozZzZhVzUyYjJ4MlpXUlFZWEowYVdWeklqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcDFjbXdpT25zaVFIWmhiSFZsSWpvaWFYQm1jem92TDIxNVEwbEVJaXdpUUhSNWNHVWlPaUo0YzJRNllXNTVWVkpKSW4wc0ltZDRPbWR2ZG1WeWJtbHVaMHhoZDBOdmRXNTBjbWxsY3lJNklrTllJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2YzJsdGNHeGxMVzFsYzNOaFoyVXRjM1Z0YldGeWVTSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOekVyTURFNk1EQWlmUS4zOFVVZkpzRVk0WGx2YlpleUQwcm1KSnE1TVdZRnhwTm1aN3ItOTE3NU0yQWlqc1hHVTU1dFJUTnVjbEdBVXkwVnBMSDdJZm45bXV0LUpxYmFoN3RHUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tsdVptOXliV0YwYVc5dVUyVmpkWEpwZEhsUWIyeHBZMmxsYzE4NU56a2lMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZTVzVtYjNKdFlYUnBiMjVUWldOMWNtbDBlVkJ2YkdsamFXVnpJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpFck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcEpibVp2Y20xaGRHbHZibE5sWTNWeWFYUjVVRzlzYVdOcFpYTmZPVGM1STJOeklpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkhUU0lzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlN3aVozZzZiV2x0WlZSNWNHVnpJam9pZG1sa1pXOHZkbTVrTG5KaFpHZGhiV1YwZEc5dmJITXVjMjFoWTJ0bGNpSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOekVyTURFNk1EQWlmUS5ZRksyVG16UG1zdUEtd3kzWExJazF2WHVHUzhuTUlmU194czZqZ0V2cUowSndqVXhFRGdRaFdCTXVRaXJnZDFYaVQyV05fTVlZZXd4UUJHMHNKWEl5QSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tsdVptOXliV0YwYVc5dVUyVmpkWEpwZEhsU2FYTnJUV0Z1WVdkbGJXVnVkRjgzTmpFaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlNXNW1iM0p0WVhScGIyNVRaV04xY21sMGVWSnBjMnROWVc1aFoyVnRaVzUwSWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56RXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBKYm1admNtMWhkR2x2YmxObFkzVnlhWFI1VW1semEwMWhibUZuWlcxbGJuUmZOell4STJOeklpd2laM2c2ZFhKc0lqcDdJa0IyWVd4MVpTSTZJbWx3Wm5NNkx5OXRlVU5KUkNJc0lrQjBlWEJsSWpvaWVITmtPbUZ1ZVZWU1NTSjlMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpUUnlJc0ltZDRPbWx1ZG05c2RtVmtVR0Z5ZEdsbGN5STZleUpBYVdRaU9pSmxlRHBNWldkaGJGQmxjbk52Ymw4M01USWpZM01pZlN3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMak5uY0hBdWJXTjJhV1JsYnkxMVpTMWpiMjVtYVdjcmVHMXNJbjBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTVNzd01Ub3dNQ0o5LlppM2ZSc1pDQUJpU0VPZzl5MGtjNGllWHNYZk9DT1o0bDlPY1U3a3Q2LUtfQXFkdDBMam9DODdrTU9Mcmo5OHBWQ0JGemFjZm52OG12alJVMU5GeEVnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa3hsWjJGc2JIbENhVzVrYVc1blFXTjBYemd6T1NJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwTVpXZGhiR3g1UW1sdVpHbHVaMEZqZENKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16Y3hLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeHNlVUpwYm1ScGJtZEJZM1JmT0RNNUkyTnpJaXdpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pU1U4aUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMHNJbWQ0T21sdWRtOXNkbVZrVUdGeWRHbGxjeUk2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkbTVrTG1sd2JHUXVZMkZ5SW4wc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01Tc3dNVG93TUNKOS5YazJlTXNsVFRwUnFZcGhnazRLZ0laYlFuV3hhVlBMYWlqNWFDX3V6eWFhTXBWcmFVaW9MWjdCM0ZFa09sUHU5d2tydWY3aDdkbEcwNWhxeUpVWmZRdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2s5d1pYSmhkR2x2Ym1Gc1UyVmpkWEpwZEhsZk5UZzFJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPazl3WlhKaGRHbHZibUZzVTJWamRYSnBkSGtpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPazl3WlhKaGRHbHZibUZzVTJWamRYSnBkSGxmTlRnMUkyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpDVGlJc0ltZDRPblZ5YkNJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZNMmR3WkdGemFDMXhiMlV0Y21Wd2IzSjBLM2h0YkNKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLm9FeTYzMl9aVllsTENvNlRNRTc2SERBZWxZV3FUQU9ybUxsMGdMTUFSSEFST1Q3QlVGUzlwSXRGNVpjLWNUSGhvMnNzU1I3QmZEUVZNczk1ajJsYTl3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEJvZVhOcFkyRnNVMlZqZFhKcGRIbGZNVE16SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2xCb2VYTnBZMkZzVTJWamRYSnBkSGtpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbEJvZVhOcFkyRnNVMlZqZFhKcGRIbGZNVE16STJOeklpd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lXVlFpTENKbmVEcHBiblp2YkhabFpGQmhjblJwWlhNaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4UVpYSnpiMjVmTnpFeUkyTnpJbjBzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlN3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMbTl3Wlc1NGJXeG1iM0p0WVhSekxXOW1abWxqWldSdlkzVnRaVzUwTG5kdmNtUndjbTlqWlhOemFXNW5iV3d1YzNSNWJHVnpLM2h0YkNKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLjN2bDBhakdsSjdMemhnU3R5bFZIOUlwRUZRNWxRclZVTUZUU0d5RlJyWko4YWt6MHViWGlIWGVTR3BmZmdreDZBblRQaURuMFBRN2pWY3FFbTk5a3pRIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEJ5YjJOMWNtVnRaVzUwVFdGdVlXZGxiV1Z1ZEZObFkzVnlhWFI1WHpJd055SXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcFFjbTlqZFhKbGJXVnVkRTFoYm1GblpXMWxiblJUWldOMWNtbDBlU0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjeUt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZVSEp2WTNWeVpXMWxiblJOWVc1aFoyVnRaVzUwVTJWamRYSnBkSGxmTWpBM0kyTnpJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5TENKbmVEcHBiblp2YkhabFpGQmhjblJwWlhNaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4UVpYSnpiMjVmTnpFeUkyTnpJbjBzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDNadVpDNXBjR3hrTG5KaGR5SXNJbWQ0T21kdmRtVnlibWx1WjB4aGQwTnZkVzUwY21sbGN5STZJa05hSW4wc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01pc3dNVG93TUNKOS56LUtzaGFRQUhXNXhWcUFoNG1keWV4R3RkWVdNay14SWxzZG5JR0Zzb3FhYnJ3THRLOEdFcGZpZFNSbnNWOGM0eVd1SnVvOVlvdnlNYVZxeENBWFFZZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xCeWIyUjFZM1JUWldOMWNtbDBlVjg0TVRVaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlVISnZaSFZqZEZObFkzVnlhWFI1SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56SXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBRY205a2RXTjBVMlZqZFhKcGRIbGZPREUxSTJOeklpd2laM2c2ZFhKc0lqcDdJa0IyWVd4MVpTSTZJbWx3Wm5NNkx5OXRlVU5KUkNJc0lrQjBlWEJsSWpvaWVITmtPbUZ1ZVZWU1NTSjlMQ0puZURwdGFXMWxWSGx3WlhNaU9pSmhjSEJzYVdOaGRHbHZiaTkyYm1RdWJXWnRjQ0lzSW1kNE9tZHZkbVZ5Ym1sdVoweGhkME52ZFc1MGNtbGxjeUk2SWtwRklpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5peHpMS0EtbVFjVXJGZ0xaenpYdFdWakdSOWxjQndmbzBGeUxqMXBkN1RyS0tOc1NfZkxkM0EwM19pSC1ONy1BUEJTd0k5XzFLSFNYMGZWRDYwUE5TdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xKdmJHVkJibVJTWlhOd2IyNXphV0pwYkdsMGFXVnpYekV6TlNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwU2IyeGxRVzVrVW1WemNHOXVjMmxpYVd4cGRHbGxjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjeUt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZVbTlzWlVGdVpGSmxjM0J2Ym5OcFltbHNhWFJwWlhOZk1UTTFJMk56SWl3aVozZzZaMjkyWlhKdWFXNW5UR0YzUTI5MWJuUnlhV1Z6SWpvaVZra2lMQ0puZURwcGJuWnZiSFpsWkZCaGNuUnBaWE1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hRWlhKemIyNWZOekV5STJOekluMHNJbWQ0T20xcGJXVlVlWEJsY3lJNkltRndjR3hwWTJGMGFXOXVMM1p1WkM1cWIyOXpkQzVxYjJSaExXRnlZMmhwZG1VaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOeklyTURFNk1EQWlmUS5ldUFrOTVrYlFCVFRzRi1ZVzc5bGdIQ3B1MWY3RzBKN0VGWG9talJjWTMwbnI2T3MyTkF0bEtmSUdMbFhvZGZ2X2djYXJTaTNhMEhtel9IZDlOV3hrdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xObFkzVnlhWFI1U1c1amFXUmxiblJOWVc1aFoyVnRaVzUwWHpFeE1pSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcFRaV04xY21sMGVVbHVZMmxrWlc1MFRXRnVZV2RsYldWdWRDSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemN5S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlUyVmpkWEpwZEhsSmJtTnBaR1Z1ZEUxaGJtRm5aVzFsYm5SZk1URXlJMk56SWl3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMbVYwYzJrdWFYQjBkblZsY0hKdlptbHNaU3Q0Yld3aUxDSm5lRHBwYm5admJIWmxaRkJoY25ScFpYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbWR2ZG1WeWJtbHVaMHhoZDBOdmRXNTBjbWxsY3lJNklrMVVJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjeUt6QXhPakF3SW4wLlp1Qm85Vkthem9hejBQUndJZnVwMkJ1MC0tUUtiMzhSc0hhQTUydVZobE5lYnA5Z19kM2Y1b0F2eGNHYVktcjV0ZUEwaWh2TlpnakYtR0JDZV9pSXVnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbE5sY25acFkyVkJaM0psWlcxbGJuUlBabVpsY2w4ME5qSWlMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZVMlZ5ZG1salpVRm5jbVZsYldWdWRFOW1abVZ5SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56SXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBUWlhKMmFXTmxRV2R5WldWdFpXNTBUMlptWlhKZk5EWXlJMk56SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSlVWQ0lzSW1kNE9tMXBiV1ZVZVhCbGN5STZJblpwWkdWdkwyMWhkSEp2YzJ0aElpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5NS05ya2FnMzM0bXNUTEtCMVBITm51RExtMGFyYWY2dUtCa18xVGlObW1rWXcxdHFKNUVTTmxBb2FqeGxXcXVvcVpsTVhHWktPN3M2dFlKNmVnb1pMdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xWelpYSkViMk4xYldWdWRHRjBhVzl1VFdGcGJuUmxibUZ1WTJWZk9EZ3dJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPbFZ6WlhKRWIyTjFiV1Z1ZEdGMGFXOXVUV0ZwYm5SbGJtRnVZMlVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01pc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbFZ6WlhKRWIyTjFiV1Z1ZEdGMGFXOXVUV0ZwYm5SbGJtRnVZMlZmT0Rnd0kyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwMWNtd2lPbnNpUUhaaGJIVmxJam9pYVhCbWN6b3ZMMjE1UTBsRUlpd2lRSFI1Y0dVaU9pSjRjMlE2WVc1NVZWSkpJbjBzSW1kNE9tZHZkbVZ5Ym1sdVoweGhkME52ZFc1MGNtbGxjeUk2SWxORklpd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkR0Z0Y0MxaGNHVjRMWFZ3WkdGMFpTMWpiMjVtYVhKdEluMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNaXN3TVRvd01DSjkuNDBQTXljWTlHRWd2SG04ZEdQNEtVMmJaYW1VYU9oQWV1UEZpUmpJTHdpZHpialROM0NOalA5M1lmMkZQTzFfdFRQUHZjRVNmMVFuM05mM3BrN3hLSGciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rMWxZWE4xY21WZk5UWTFJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPazFsWVhOMWNtVWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTWlzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rMWxZWE4xY21WZk5UWTFJMk56SWl3aWFIUjBjSE56WTJobGJXRTZaR1Z6WTNKcGNIUnBiMjRpT2lKVFRFUkpTMFlpTENKbmVEcHNaV2RoYkVSdlkzVnRaVzUwY3lJNlczc2lRR2xrSWpvaVpYZzZRV05qWlhOelEyOXVkSEp2YkUxaGJtRm5aVzFsYm5SZk9EazFJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEJjM05sZEhOTllXNWhaMlZ0Wlc1MFh6SXlNaU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZRblZ6YVc1bGMzTkRiMjUwYVc1MWFYUjVUV1ZoYzNWeVpYTmZOalEySTJOekluMHNleUpBYVdRaU9pSmxlRHBEYUdGdVoyVkJibVJEYjI1bWFXZDFjbUYwYVc5dVRXRnVZV2RsYldWdWRGODFOaklqWTNNaWZTeDdJa0JwWkNJNkltVjRPa052YlhCc2FXRnVZMlZCYzNOMWNtRnVZMlZmT1RjMkkyTnpJbjBzZXlKQWFXUWlPaUpsZURwRGIzQjVjbWxuYUhSQmJtUkpiblJsYkd4bFkzUjFZV3hRY205d1pYSjBlVVJ2WTNWdFpXNTBYelUxTXlOamN5SjlMSHNpUUdsa0lqb2laWGc2UTNWemRHOXRaWEpCZFdScGRHbHVaMUpwWjJoMGMxODBOVElqWTNNaWZTeDdJa0JwWkNJNkltVjRPa04xYzNSdmJXVnlSR0YwWVVGalkyVnpjMVJsY20xelh6a3dNeU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZRM1Z6ZEc5dFpYSkVZWFJoVUhKdlkyVnpjMmx1WjFSbGNtMXpYelV6TUNOamN5SjlMSHNpUUdsa0lqb2laWGc2UkdGMFlWQnliM1JsWTNScGIyNVNaV2QxYkdGMGFXOXVUV1ZoYzNWeVpYTmZNVEV3STJOekluMHNleUpBYVdRaU9pSmxlRHBFWlhabGJHOXdiV1Z1ZEVONVkyeGxVMlZqZFhKcGRIbGZOalV4STJOekluMHNleUpBYVdRaU9pSmxlRHBFYjJOMWJXVnVkRU5vWVc1blpWQnliMk5sWkhWeVpYTmZOREU1STJOekluMHNleUpBYVdRaU9pSmxlRHBGYlhCc2IzbGxaVkpsYzNCdmJuTnBZbWxzYVhScFpYTmZORGNqWTNNaWZTeDdJa0JwWkNJNkltVjRPa1Z1ZG1seWIyNXRaVzUwWVd4SmJYQmhZM1JTWlhCdmNuUmZOemMxSTJOekluMHNleUpBYVdRaU9pSmxlRHBIYjNabGNtNXRaVzUwU1c1MlpYTjBhV2RoZEdsdmJrMWhibUZuWlcxbGJuUmZOakU1STJOekluMHNleUpBYVdRaU9pSmxlRHBKYm1admNtMWhkR2x2YmxObFkzVnlhWFI1VDNKbllXNXBlbUYwYVc5dVh6WTFOeU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZTVzVtYjNKdFlYUnBiMjVUWldOMWNtbDBlVkJ2YkdsamFXVnpYemszT1NOamN5SjlMSHNpUUdsa0lqb2laWGc2U1c1bWIzSnRZWFJwYjI1VFpXTjFjbWwwZVZKcGMydE5ZVzVoWjJWdFpXNTBYemMyTVNOamN5SjlMSHNpUUdsa0lqb2laWGc2VEdWbllXeHNlVUpwYm1ScGJtZEJZM1JmT0RNNUkyTnpJbjBzZXlKQWFXUWlPaUpsZURwUGNHVnlZWFJwYjI1aGJGTmxZM1Z5YVhSNVh6VTROU05qY3lKOUxIc2lRR2xrSWpvaVpYZzZVR2g1YzJsallXeFRaV04xY21sMGVWOHhNek1qWTNNaWZTeDdJa0JwWkNJNkltVjRPbEJ5YjJOMWNtVnRaVzUwVFdGdVlXZGxiV1Z1ZEZObFkzVnlhWFI1WHpJd055TmpjeUo5TEhzaVFHbGtJam9pWlhnNlVISnZaSFZqZEZObFkzVnlhWFI1WHpneE5TTmpjeUo5TEhzaVFHbGtJam9pWlhnNlVtOXNaVUZ1WkZKbGMzQnZibk5wWW1sc2FYUnBaWE5mTVRNMUkyTnpJbjBzZXlKQWFXUWlPaUpsZURwVFpXTjFjbWwwZVVsdVkybGtaVzUwVFdGdVlXZGxiV1Z1ZEY4eE1USWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9sTmxjblpwWTJWQlozSmxaVzFsYm5SUFptWmxjbDgwTmpJalkzTWlmU3g3SWtCcFpDSTZJbVY0T2xWelpYSkViMk4xYldWdWRHRjBhVzl1VFdGcGJuUmxibUZ1WTJWZk9EZ3dJMk56SW4xZGZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5BWkZrVjFZeTZEcDJWNERfdkRWejMyYXc4d3AzeW4wejcwczlvbFNsMGxRSVNBVF9tQlNfZG1NbEZTYXZEd1hIYjI5X3ZtaUtDQ2hadDdrakc2MDloQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOdmJuUmhZM1JKYm1admNtMWhkR2x2Ymw4eU1qa2lMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZRMjl1ZEdGamRFbHVabTl5YldGMGFXOXVJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpJck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcERiMjUwWVdOMFNXNW1iM0p0WVhScGIyNWZNakk1STJOeklpd2laM2c2WlcxaGFXd2lPaUpoWjA5d2NVaGhZeUlzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01pc3dNVG93TUNKOS5vc3ktT1VYY283cDkxMU94dHJaeUt2WWdFQVdvQmtGeTFKRHp6S3dsLXRKcXpNbVpqZjN3QUhGWjlRcEQ1UF9DQW1UeEZncDV4UnZOOEhDTUU5T2tEdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNSRzlqZFcxbGJuUmZOREU0SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2t4bFoyRnNSRzlqZFcxbGJuUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTWlzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzUkc5amRXMWxiblJmTkRFNEkyTnpJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2ZG01a0xuQmhkR2xsYm5SbFkyOXRiWE5rYjJNaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMHNJbWQ0T21sdWRtOXNkbVZrVUdGeWRHbGxjeUk2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lRMGtpZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjeUt6QXhPakF3SW4wLnY5S3h5NGlKQjBwbzNnVjQ0d1lsWlhpNkZSLTdBZERTSnlaVm5xSjNLSU5yU2NJNGZRb0dBT0FSWnJETnY5THVhcUJ0anhOQUpFbUJ5RXJGVW1Yd2ZnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1JoZEdGUWIzSjBZV0pwYkdsMGVWODNPVGNpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UkdGMFlWQnZjblJoWW1sc2FYUjVJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpJck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcEVZWFJoVUc5eWRHRmlhV3hwZEhsZk56azNJMk56SWl3aVozZzZiR1ZuWVd4RWIyTjFiV1Z1ZENJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkVSdlkzVnRaVzUwWHpReE9DTmpjeUo5TENKbmVEcGtiMk4xYldWdWRHRjBhVzl1Y3lJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2WkdWc1pYUnBiMjVOWlhSb2IyUnpJam9pVDFoTlEyTnFWbE1pTENKbmVEcG1iM0p0WVhSeklqb2lXVTVrVW5oR1YyNGlMQ0puZURwd2NtbGphVzVuSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBrWld4bGRHbHZibFJwYldWbWNtRnRaU0k2SW5wNldVVk5jbTEzSWl3aVozZzZiV1ZoYm5NaU9pSk1lbTlIWW1GbVVDSXNJbWQ0T25KbGMyOTFjbU5sSWpvaVYyWlljbXhpYVdzaUxDSm5lRHBqYjI1MFlXTjBTVzVtYjNKdFlYUnBiMjRpT25zaVFHbGtJam9pWlhnNlEyOXVkR0ZqZEVsdVptOXliV0YwYVc5dVh6SXlPU05qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5EYmM0cFBnenJ5VWlzaU1aSm5ydHAzTUVFd1ZZLTZVbG9TZEVuMWRQWGFaeTFpNE1YRkxLMDNyc3puNGZGa3JRY2FIelZoZGRJYVhlcUEtMUJncnFMUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRkJZMk52ZFc1MFJYaHdiM0owWHpVd01pSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEVZWFJoUVdOamIzVnVkRVY0Y0c5eWRDSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemN6S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlJHRjBZVUZqWTI5MWJuUkZlSEJ2Y25SZk5UQXlJMk56SWl3aVozZzZabTl5YldGMFZIbHdaU0k2SW1Gd2NHeHBZMkYwYVc5dUwyTmpZMlY0SWl3aVozZzZjbVZ4ZFdWemRGUjVjR1VpT2lKQlVFa2lMQ0puZURwaFkyTmxjM05VZVhCbElqb2laR2xuYVhSaGJDSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOek1yTURFNk1EQWlmUS5lM3owVDZ6VXZrTkVsNEROOE85NTRjQURIWHM3Vy1kbWxzOW1xNS1xa1c0ZG1NSmVmc3FaTmN3V2xiUVpTWi1vLXB0TlFfYVhHVzE1RmVyT3NLV2NIUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRlVjbUZ1YzJabGNsOHpOVEVpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UkdGMFlWUnlZVzV6Wm1WeUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOek1yTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwRVlYUmhWSEpoYm5ObVpYSmZNelV4STJOeklpd2laM2c2YzJOdmNHVWlPaUpOYVZSaVZVMVZieUlzSW1kNE9uSmxZWE52YmlJNkluSnFRWGRZUkhWcEluMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNeXN3TVRvd01DSjkualF3aDl2MGhUZm9zT0E4NHdOT2E1WTAxM2Nzc25tZS1hbUxBaGxfUFlWdGdjdnpRSEFEbDJTazdjcVpjUzE1QzZiNFVoUGl2V2hFOEEtTDdkb3JkaGciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVNXNXpkSEoxWTNScGIyNXpYek14TUNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRGRYTjBiMjFsY2tsdWMzUnlkV04wYVc5dWN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemN6S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlEzVnpkRzl0WlhKSmJuTjBjblZqZEdsdmJuTmZNekV3STJOeklpd2laM2c2ZEdWeWJYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeEViMk4xYldWdWRGODBNVGdqWTNNaWZTd2laM2c2YldWaGJuTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeEViMk4xYldWdWRGODBNVGdqWTNNaWZYMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNeXN3TVRvd01DSjkuUFB3NDJmUGVWMEoyZkZjcnBOWVNxdkhMOFI0blhieldXNFEwVnpqblo5ZFByM1dUdWR6dnhmZEoxc2VZdjhSbEhXQzRBSGFfc2V2aFlVUjBabmVJVlEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9sTjFZa052Ym5SeVlXTjBiM0pmTnpjeklpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9sTjFZa052Ym5SeVlXTjBiM0lpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM015c3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbE4xWWtOdmJuUnlZV04wYjNKZk56Y3pJMk56SWl3aVozZzZZMjl0YlhWdWFXTmhkR2x2YmsxbGRHaHZaSE1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hFYjJOMWJXVnVkRjgwTVRnalkzTWlmU3dpWjNnNmJHVm5ZV3hPWVcxbElqb2lWRmh4UlhaaFdWa2lMQ0puZURwaGNIQnNhV05oWW14bFNuVnlhWE5rYVdOMGFXOXVJam9pVkZJaUxDSm5lRHBwYm1admNtMWhkR2x2YmtSdlkzVnRaVzUwY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkVSdlkzVnRaVzUwWHpReE9DTmpjeUo5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjekt6QXhPakF3SW4wLl9BSmdkeDhSLVA3NlBWc3VvRXJSQklEVnlEeGtad2ZKOGFlRW0wUmUxTTZiYXYzVk92S1NzcHFXSGZkN3RVSUZfVGJ6VlNjMWlyV2dNSlJjY0pDS25nIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEpsYzI5MWNtTmxYek0wT0NJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwU1pYTnZkWEpqWlNKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16Y3pLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2VW1WemIzVnlZMlZmTXpRNEkyTnpJaXdpWjNnNllXZG5jbVZuWVhScGIyNVBabEpsYzI5MWNtTmxjeUk2ZXlKQWFXUWlPaUpsZURwU1pYTnZkWEpqWlY4ek5EZ2pZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM015c3dNVG93TUNKOS5XSy1QVlU5ek94UWhFRFJrUjRrNURDVVp2ZmVWMWpoVmhPbG5PUERaSkI1YVhwUDlVLXVFZWZrTXM3elhPYVdna1M0eEozWC1QMGNMSngzeG05LVBwZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xacGNuUjFZV3hTWlhOdmRYSmpaVjgxTWlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwV2FYSjBkV0ZzVW1WemIzVnlZMlVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM015c3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbFpwY25SMVlXeFNaWE52ZFhKalpWODFNaU5qY3lJc0ltZDRPbXhwWTJWdWMyVWlPaUpVVDFKUlZVVXRNUzR4SWl3aVozZzZZMjl3ZVhKcFoyaDBUM2R1WldSQ2VTSTZleUpBYVdRaU9pSmxlRHBNWldkaGJGQmxjbk52Ymw4M01USWpZM01pZlN3aVozZzZjbVZ6YjNWeVkyVlFiMnhwWTNraU9pSlJUV1ZrVTJkMVlpSXNJbWQ0T21GblozSmxaMkYwYVc5dVQyWlNaWE52ZFhKalpYTWlPbnNpUUdsa0lqb2laWGc2VW1WemIzVnlZMlZmTXpRNEkyTnpJbjE5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpNck1ERTZNREFpZlEuY09pSnllajlBc2xZei1CRjZDTGtFaFBsSnhSeFptWXh5VkNLMXhmTFpKU1pZZEpUWk5PNGZPeVBsWGhiRlRSZ2dwYXB3UjFjbEF0Y3REYTlGR0FxVWciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9sUmxjbTF6UVc1a1EyOXVaR2wwYVc5dWMxODROVElpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2VkdWeWJYTkJibVJEYjI1a2FYUnBiMjV6SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56TXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBVWlhKdGMwRnVaRU52Ym1ScGRHbHZibk5mT0RVeUkyTnpJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5TENKbmVEcG9ZWE5vSWpvaVMxZDVVMGhPVlVjaWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3pLekF4T2pBd0luMC5US3BNcVljZmotMFVxQ0dOalZVd0ZpRTAyajIycXFXQWRuUlZ6Q2lZX2QtUW1SUllMZzVmRGRlZGI3WWk5WlZDYVU2VVJTNmpoX3Q2RnBLSm11bUdnQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkUVUxVnVhWFJmTWpBNUlpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rZFFVMVZ1YVhRaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNNeXN3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2tkUVUxVnVhWFJmTWpBNUkyTnpJaXdpWjNnNmMyVmpiMjVrY3lJNk5Ea3NJbWQ0T20xcGJuVjBaWE1pT2pJMUxDSm5lRHBrWldkeVpXVnpJam90T1Rrc0ltZDRPbVJsWTJsdFlXeHpJanA3SWtCMllXeDFaU0k2TUM0eU9Td2lRSFI1Y0dVaU9pSjRjMlE2Wm14dllYUWlmWDBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTXlzd01Ub3dNQ0o5LjB1cFNEeEhGYjdYYXRzSmhuV19mZzFTTGNORlRvNHJJZ2ZMYXBFcHNyX3E3QnJ3b1hBcG5MLXNOMGFrLUotY2VicGxaZUxTQVI2OWx0b0EwTnQ0TEFnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa2RRVTB4dlkyRjBhVzl1WHpVeE1DSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEhVRk5NYjJOaGRHbHZiaUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSMUJUVEc5allYUnBiMjVmTlRFd0kyTnpJaXdpWjNnNmJHRjBhWFIxWkdVaU9uc2lRR2xrSWpvaVpYZzZSMUJUVlc1cGRGOHlNRGtqWTNNaWZTd2laM2c2WVd4MGFYUjFaR1VpT2lKNVVWbGhUV1ZsWlNJc0ltZDRPbU55Y3lJNklrTlNVeUlzSW1kNE9teHZibWRwZEhWa1pTSTZleUpBYVdRaU9pSmxlRHBIVUZOVmJtbDBYekl3T1NOamN5SjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNemN6S3pBeE9qQXdJbjAuT3R5T1JBZkkxaHRaWE1Md0FHSFljZEFFV0FNeU1qbUdScVRLdGUwWkRjWG5ldjhrYkU5MWtNYWdOUHhQRlNGSkNIWk5Fa2FhNTJlT1JjaUpXWGtEZVEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rVnVaWEpuZVUxcGVGOHlNRGdpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2Ulc1bGNtZDVUV2w0SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56TXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBGYm1WeVozbE5hWGhmTWpBNEkyTnpJaXdpWjNnNmNtVnVaWGRoWW14bFJXNWxjbWQ1SWpwN0lrQjJZV3gxWlNJNk1pNDJOeXdpUUhSNWNHVWlPaUo0YzJRNlpteHZZWFFpZlN3aVozZzZZWFIwWVdsdWJXVnVkRVJoZEdVaU9uc2lRSFpoYkhWbElqb2lNakF5TlMweE1DMHdOQ0lzSWtCMGVYQmxJam9pZUhOa09tUmhkR1VpZlN3aVozZzZhRzkxY214NVEyRnlZbTl1Um5KbFpVVnVaWEpuZVNJNmV5SkFkbUZzZFdVaU9qSXVOakVzSWtCMGVYQmxJam9pZUhOa09tWnNiMkYwSW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56TXJNREU2TURBaWZRLkQ5STNkZWNOUmNxSVRmZXRuMkR1QUVXME1HeVk5VnNlNS1wUkVVQl9WT2xUcFZuUzZ3WURDOEpVZkxSdWxTMDh3Vm43U0NydHdBR1VzdEI1Q3ozV0t3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa2RRVTFWdWFYUmZNVFFpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UjFCVFZXNXBkQ0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSMUJUVlc1cGRGOHhOQ05qY3lJc0ltZDRPbk5sWTI5dVpITWlPak13TENKbmVEcHRhVzUxZEdWeklqbzBNeXdpWjNnNlpHVm5jbVZsY3lJNkxUa3dMQ0puZURwa1pXTnBiV0ZzY3lJNmV5SkFkbUZzZFdVaU9qQXVOVFFzSWtCMGVYQmxJam9pZUhOa09tWnNiMkYwSW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56TXJNREU2TURBaWZRLjRwN1JKTFNyb2VkcjRTVlUwNmRGcmFxVDgzNlBYQTFNTzlsNVhVTVJGaUJsZTdrQWlWRGNXbkE4bkphV3RxWjIyUF9JekJTUktwMXJvOFQ2dHZKUW93IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa2RRVTB4dlkyRjBhVzl1WHpNek9TSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEhVRk5NYjJOaGRHbHZiaUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSMUJUVEc5allYUnBiMjVmTXpNNUkyTnpJaXdpWjNnNmJHRjBhWFIxWkdVaU9uc2lRR2xrSWpvaVpYZzZSMUJUVlc1cGRGOHhOQ05qY3lKOUxDSm5lRHBoYkhScGRIVmtaU0k2SW1ac1FYZFNXVTlwSWl3aVozZzZZM0p6SWpvaVExSlRJaXdpWjNnNmJHOXVaMmwwZFdSbElqcDdJa0JwWkNJNkltVjRPa2RRVTFWdWFYUmZNVFFqWTNNaWZYMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNeXN3TVRvd01DSjkubkI3VGE5eXI1N2FYU3JsWmNmVWtjdmU5X2tsYUxta3dNZ2l6eS1CWkdyTzkzdXFUMm54ZWp0bEQ5d2lxUGxWdXdZRjd0N2dhcWxWZWViYjg1UUtRQmciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9sSmxjMjkxY21ObFh6STRPQ0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBTWlhOdmRYSmpaU0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZVbVZ6YjNWeVkyVmZNamc0STJOeklpd2laM2c2WVdkbmNtVm5ZWFJwYjI1UFpsSmxjMjkxY21ObGN5STZleUpBYVdRaU9pSmxlRHBTWlhOdmRYSmpaVjh5T0RnalkzTWlmWDBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTXlzd01Ub3dNQ0o5LlBQaVVXVjNaT3VYQWFDQkp0ZUp3UlVGbjJGZXZfQjJ4UmE1bmRaRk1qb1BWZ0dIaGhWSXRKZ21pZFUzNldteDVrcGU0UlFwSUl0SUZNOGhhUTMyMkxBIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa0YyWVdsc1lXSnBiR2wwZVZwdmJtVmZPRFl6SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tGMllXbHNZV0pwYkdsMGVWcHZibVVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM015c3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa0YyWVdsc1lXSnBiR2wwZVZwdmJtVmZPRFl6STJOeklpd2laM2c2WVdSa2NtVnpjeUk2ZXlKQWFXUWlPaUpsZURwQlpHUnlaWE56WHprNU1pTmpjeUo5TENKbmVEcGhaMmR5WldkaGRHbHZiazltVW1WemIzVnlZMlZ6SWpwN0lrQnBaQ0k2SW1WNE9sSmxjMjkxY21ObFh6STRPQ05qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3pLekF4T2pBd0luMC5lcmVFMUdFZGRLSmRJbjR5Tm5sS1I1SVdmSW1kU0pxeVd1RmpXMGo3THEydzI1Y0o4UlRmeTVIR2JMNmNLOVc4UWczZUs1aGdRUC1vWWZOU2htWG9ZUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNSRzlqZFcxbGJuUmZNVE00SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2t4bFoyRnNSRzlqZFcxbGJuUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTXlzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzUkc5amRXMWxiblJmTVRNNEkyTnpJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2ZG01a0xtUmhkR0ZzYjJjaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMHNJbWQ0T21sdWRtOXNkbVZrVUdGeWRHbGxjeUk2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lSRW9pZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjekt6QXhPakF3SW4wLmZJalNLMDZscUFSQjJBXzdnN2xpUWFYN0JHRG0zSGNKQlpyS3N0T21tNy1Ea1k3akFIMEpDRm1rdzJkWXdWU1puTHRFVU1iYzJGU1MyOVdLc1VQYlVnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbGRoZEdWeVZYTmhaMlZGWm1abFkzUnBkbVZ1WlhOelh6YzVPQ0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBYWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemMwS3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlYyRjBaWEpWYzJGblpVVm1abVZqZEdsMlpXNWxjM05mTnprNEkyTnpJaXdpWjNnNlkyVnlkR2xtYVdOaGRHbHZibk1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hFYjJOMWJXVnVkRjh4TXpnalkzTWlmU3dpWjNnNmQyRjBaWEpWYzJGblpVVm1abVZqZEdsMlpXNWxjM01pT25zaVFIWmhiSFZsSWpveUxqWXpMQ0pBZEhsd1pTSTZJbmh6WkRwbWJHOWhkQ0o5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLnVZaVdhQzlXVm1Nb3ItNmNvTTU5Zmp5bU5aOUFwREIzQVhtYmg4RXpHN0RqZXh2OEVkbzlvSFA0bGFXMUMwQ09RbFkwUmJ4RWdPdl9DZF9FSTY1SkRBIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1Z1WlhKbmVWVnpZV2RsUldabWFXTnBaVzVqZVY4ek5qZ2lMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZSVzVsY21kNVZYTmhaMlZGWm1acFkybGxibU41SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56UXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBGYm1WeVozbFZjMkZuWlVWbVptbGphV1Z1WTNsZk16WTRJMk56SWl3aVozZzZZMlZ5ZEdsbWFXTmhkR2x2Ym5NaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4RWIyTjFiV1Z1ZEY4eE16Z2pZM01pZlN3aVozZzZjRzkzWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNNaU9uc2lRSFpoYkhWbElqb3hMamd4TENKQWRIbHdaU0k2SW5oelpEcG1iRzloZENKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16YzBLekF4T2pBd0luMC45QzVBWDhzcU40S0dMS3AwVjJVLXd1WjhVenZ6Szlyb1Jlc0xWY3ljU0RnYkFBUmU0eDI4N25XTk4yQXU5NVdaSEtURjVOdlM5alBVckdwVjF0MG95QSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRkRaVzUwWlhJaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlJHRjBZV05sYm5SbGNpSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemMwS3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlJHRjBZVU5sYm5SbGNpTmpjeUlzSW1kNE9tVnVaWEpuZVUxcGVDSTZleUpBYVdRaU9pSmxlRHBGYm1WeVozbE5hWGhmTWpBNEkyTnpJbjBzSW1kNE9tRm5aM0psWjJGMGFXOXVUMlpTWlhOdmRYSmpaWE1pT25zaVFHbGtJam9pWlhnNlFYWmhhV3hoWW1sc2FYUjVXbTl1WlY4NE5qTWpZM01pZlN3aVozZzZkMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNNaU9uc2lRR2xrSWpvaVpYZzZWMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNOZk56azRJMk56SW4wc0ltZDRPbTFoYVc1MFlXbHVaV1JDZVNJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNmJXRnVkV1poWTNSMWNtVmtRbmtpT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hRWlhKemIyNWZOekV5STJOekluMHNJbWQ0T214dlkyRjBhVzl1SWpwN0lrQnBaQ0k2SW1WNE9rRmtaSEpsYzNOZk9Ua3lJMk56SW4wc0ltZDRPbTkzYm1Wa1Fua2lPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbVZ1WlhKbmVWVnpZV2RsUldabWFXTnBaVzVqZVNJNmV5SkFhV1FpT2lKbGVEcEZibVZ5WjNsVmMyRm5aVVZtWm1samFXVnVZM2xmTXpZNEkyTnpJbjE5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpRck1ERTZNREFpZlEuTlZMUV9XVUstdFhiS2NOSk5nMlc0UFNZd1FlbFFJV204RURGOGtIUGtqOV9aSzF5cDNWUTdsaVNMOG9OSVR4QlFyeHVqdWc5MW4wZ3VIa3NIU2VQTXciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rZFFVMVZ1YVhSZk9Ea3hJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPa2RRVTFWdWFYUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTkNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rZFFVMVZ1YVhSZk9Ea3hJMk56SWl3aVozZzZjMlZqYjI1a2N5STZORGdzSW1kNE9tUmxaM0psWlhNaU9qRXlNU3dpWjNnNlpHVmphVzFoYkhNaU9uc2lRSFpoYkhWbElqb3dMamd6TENKQWRIbHdaU0k2SW5oelpEcG1iRzloZENKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16YzBLekF4T2pBd0luMC5ZYVJJS2llTGhid2NrUXZId1Y1SXA0RFg2ajNPWVBHcUt3Xy1MUnZFTmhxVVZyVW1WTHNJWGNueXVvek1Ub0Fqb0pETjE5RHVLQnlxUU9ES0luZVVDZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkUVUweHZZMkYwYVc5dVh6ZzVOeUlzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBIVUZOTWIyTmhkR2x2YmlKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16YzBLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UjFCVFRHOWpZWFJwYjI1Zk9EazNJMk56SWl3aVozZzZiR0YwYVhSMVpHVWlPbnNpUUdsa0lqb2laWGc2UjFCVFZXNXBkRjg0T1RFalkzTWlmU3dpWjNnNllXeDBhWFIxWkdVaU9pSjFkRTFEYW1wdWVTSXNJbWQ0T21OeWN5STZJa05TVXlJc0ltZDRPbXh2Ym1kcGRIVmtaU0k2ZXlKQWFXUWlPaUpsZURwSFVGTlZibWwwWHpnNU1TTmpjeUo5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLkU3RnhOX0NrRl9Gbm9ZVFp1UnI3bVJnVnhoZTh3T21Jakp5YUsxSXpidGJDbjRKQ0R2N2s2VC1DUlhYSEozRlVBRjdKNmpYUzRSTWRfQzFVNkF0cU13IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa0ZrWkhKbGMzTmZPVGt5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tGa1pISmxjM01pWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM05Dc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa0ZrWkhKbGMzTmZPVGt5STJOeklpd2laM2c2WTI5MWJuUnllVU52WkdVaU9pSkhWU0lzSW1kNE9tZHdjeUk2ZXlKQWFXUWlPaUpsZURwSFVGTk1iMk5oZEdsdmJsODRPVGNqWTNNaWZTd2laM2c2WTI5MWJuUnllVTVoYldVaU9pSmFSMk55UmxoUFZpSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS4xcjVZdWdBbkttNmRmNVhjNERHMk9jb1daczFnZHcyaXduald1eWtPVmhUUkFoMlRlT05SSm5Ndnh3ZUlDQmZQV2pvaXFkS04yMUZHOW1INHFUX1hCQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNSRzlqZFcxbGJuUmZOVFEzSWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2t4bFoyRnNSRzlqZFcxbGJuUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTkNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzUkc5amRXMWxiblJmTlRRM0kyTnpJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2YkdRcmFuTnZiaUlzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlN3aVozZzZhVzUyYjJ4MlpXUlFZWEowYVdWeklqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcG5iM1psY201cGJtZE1ZWGREYjNWdWRISnBaWE1pT2lKVVRDSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS5VeXRxaE1YTEN1VE1PQ2pnZG83Q2UxREU1c0NTSDNPVERqRTNrS1lWaWx6Q090LTJfd3NIeFpMVjI3UGdQVUE4TFdtLWo0S2RvOWppVl9sNUx5a2l1USIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xkaGRHVnlWWE5oWjJWRlptWmxZM1JwZG1WdVpYTnpYek0yTXlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwWFlYUmxjbFZ6WVdkbFJXWm1aV04wYVhabGJtVnpjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjMEt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZWMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNOZk16WXpJMk56SWl3aVozZzZZMlZ5ZEdsbWFXTmhkR2x2Ym5NaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4RWIyTjFiV1Z1ZEY4MU5EY2pZM01pZlN3aVozZzZkMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNNaU9uc2lRSFpoYkhWbElqb3lMakExTENKQWRIbHdaU0k2SW5oelpEcG1iRzloZENKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16YzBLekF4T2pBd0luMC5aSXJ1eHA1T29Ta0E5ZjNNRG1GYjJ5NkhKQzVOZFgxOGN6X21ubEx2MUliUlV3TExIbk9Xemo4Um5McDFpWGpNMWctaXI0eXZubVlJWDdZRk0wWlVDQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xKbGMyOTFjbU5sWHpJeUlpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9sSmxjMjkxY21ObElsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwU1pYTnZkWEpqWlY4eU1pTmpjeUlzSW1kNE9tRm5aM0psWjJGMGFXOXVUMlpTWlhOdmRYSmpaWE1pT25zaVFHbGtJam9pWlhnNlVtVnpiM1Z5WTJWZk1qSWpZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM05Dc3dNVG93TUNKOS4zMjduN2ZjQTJEZ0I0ZC1uR1lVNkFFUzFkbk1hcno1RUJrZzcxaE1KVzdhWVY0eHFzSUhiQ3JkM2RBSF8zQ21faHZ2ZjFOc2tNdnpuQ05vVzk5LVNYQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tGMllXbHNZV0pwYkdsMGVWcHZibVZmTnpJMklpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rRjJZV2xzWVdKcGJHbDBlVnB2Ym1VaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNOQ3N3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2tGMllXbHNZV0pwYkdsMGVWcHZibVZmTnpJMkkyTnpJaXdpWjNnNllXUmtjbVZ6Y3lJNmV5SkFhV1FpT2lKbGVEcEJaR1J5WlhOelh6azVNaU5qY3lKOUxDSm5lRHBoWjJkeVpXZGhkR2x2Yms5bVVtVnpiM1Z5WTJWeklqcDdJa0JwWkNJNkltVjRPbEpsYzI5MWNtTmxYekl5STJOekluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS56VDZCcUFJN1lwazRDOWUxdGRXelBTcFlXVjVwZmRlU3o4bXlSSjE3NFBPMXp5WVFEbmtNNVpJRE5kb2FxTjhrZmtiZ2ZZeFpGRVFvV2lqLUJSc3BjQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tWdVpYSm5lVlZ6WVdkbFJXWm1hV05wWlc1amVWODBPRElpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2Ulc1bGNtZDVWWE5oWjJWRlptWnBZMmxsYm1ONUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwRmJtVnlaM2xWYzJGblpVVm1abWxqYVdWdVkzbGZORGd5STJOeklpd2laM2c2WTJWeWRHbG1hV05oZEdsdmJuTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeEViMk4xYldWdWRGODFORGNqWTNNaWZTd2laM2c2Y0c5M1pYSlZjMkZuWlVWbVptVmpkR2wyWlc1bGMzTWlPbnNpUUhaaGJIVmxJam94TGpJMkxDSkFkSGx3WlNJNkluaHpaRHBtYkc5aGRDSjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNemMwS3pBeE9qQXdJbjAuNzRrTzEzdS1CcS1vU2xiZEFOZE1uRTBySmphM215TGt6Nm90TU4wdFlsMk9nYkVNMFNJRFE5QXVNQ0FXY0xfTVNJcXR4Q24yZjYtamkxV1FhUzR1ZFEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rUmhkR0ZqWlc1MFpYSmZPVGt5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tSaGRHRmpaVzUwWlhJaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNOQ3N3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2tSaGRHRmpaVzUwWlhKZk9Ua3lJMk56SWl3aVozZzZaVzVsY21kNVRXbDRJanA3SWtCcFpDSTZJbVY0T2tWdVpYSm5lVTFwZUY4eU1EZ2pZM01pZlN3aVozZzZZV2RuY21WbllYUnBiMjVQWmxKbGMyOTFjbU5sY3lJNmV5SkFhV1FpT2lKbGVEcEJkbUZwYkdGaWFXeHBkSGxhYjI1bFh6Y3lOaU5qY3lKOUxDSm5lRHAzWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemN5STZleUpBYVdRaU9pSmxlRHBYWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemMxOHpOak1qWTNNaWZTd2laM2c2YldGcGJuUmhhVzVsWkVKNUlqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcHRZVzUxWm1GamRIVnlaV1JDZVNJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNmJHOWpZWFJwYjI0aU9uc2lRR2xrSWpvaVpYZzZRV1JrY21WemMxODVPVElqWTNNaWZTd2laM2c2YjNkdVpXUkNlU0k2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2Wlc1bGNtZDVWWE5oWjJWRlptWnBZMmxsYm1ONUlqcDdJa0JwWkNJNkltVjRPa1Z1WlhKbmVWVnpZV2RsUldabWFXTnBaVzVqZVY4ME9ESWpZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM05Dc3dNVG93TUNKOS5aSjVSLU9VaFA2WElObHJ6LUpzQWRrOUkwUFdObzNYSG9aYjJwQXdEaDVHdnowQ2hSUlhjRG50RmlmQ0luam9JODJMYTl4NVZoeHNOMVVrMk4xZEJBUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRmpaVzUwWlhKQmJHeHZZMkYwYVc5dVh6WXpPQ0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBFWVhSaFkyVnVkR1Z5UVd4c2IyTmhkR2x2YmlKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16YzBLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UkdGMFlXTmxiblJsY2tGc2JHOWpZWFJwYjI1Zk5qTTRJMk56SWl3aVozZzZjRzl5ZEU1MWJXSmxjaUk2TVN3aVozZzZjbVZtWlhKelZHOGlPbnNpUUdsa0lqb2laWGc2UkdGMFlXTmxiblJsY2w4NU9USWpZM01pZlN3aVozZzZabXh2YjNJaU9pSlpSRWhXYzJSVlR5SXNJbWQ0T25CaGRHTm9VR0Z1Wld3aU9pSkdkMU5CUW1adGN5SXNJbWQ0T25KaFkydE9kVzFpWlhJaU9pSjJWVU5RWTJWQllTSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS5STndadmdEemV0emJLVDRNdnlnZGtneWdDZFIxcldYN0lfVEpuZkJ2UUdKaVpJaGoxeC0waXlIanFrZm9HYnBJUWhOYlkwV3prQkZqMUtDY1JRQ3d4QSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tsdWRHVnlZMjl1Ym1WamRHbHZibEJ2YVc1MFNXUmxiblJwWm1sbGNsODJNVFlpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2U1c1MFpYSmpiMjV1WldOMGFXOXVVRzlwYm5SSlpHVnVkR2xtYVdWeUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwSmJuUmxjbU52Ym01bFkzUnBiMjVRYjJsdWRFbGtaVzUwYVdacFpYSmZOakUySTJOeklpd2laM2c2YldGalFXUmtjbVZ6Y3lJNklqRXhPbU5sT2poa09qVm1Pa1prT2tJd0lpd2laM2c2YVhCQlpHUnlaWE56SWpvaU1qSXVOalV1TXpFd0xqUWlMQ0puZURwamIyMXdiR1YwWlVsUVNTSTZJazlwWW5SdmNsRldJaXdpWjNnNlpHRjBZV05sYm5SbGNrRnNiRzlqWVhScGIyNGlPbnNpUUdsa0lqb2laWGc2UkdGMFlXTmxiblJsY2tGc2JHOWpZWFJwYjI1Zk5qTTRJMk56SW4wc0ltZDRPbWx3YVZSNWNHVWlPaUpNYVc1cklpd2laM2c2YVhCcFVISnZkbWxrWlhJaU9pSm1jV1pPWmtwWFNpSXNJbWQ0T25Od1pXTnBabWxqVUdGeVlXMWxkR1Z5Y3lJNklrTlRWMVJQV21aekluMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNOQ3N3TVRvd01DSjkuTFg0dE9JZHRzYlNfcVNMdnQ1eW9xSk5rTDVOcmRrbmRHUVhvZVNsQW45OGNZYU1WZTQ3dktrX01CeE1OUGpnUVVLRkN1VEFXS2FIcTdFY2xaU3p0MXciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rbHVkR1Z5Ym1WMFUyVnlkbWxqWlZCeWIzWnBaR1Z5WHpJeElpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rbHVkR1Z5Ym1WMFUyVnlkbWxqWlZCeWIzWnBaR1Z5SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56UXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBKYm5SbGNtNWxkRk5sY25acFkyVlFjbTkyYVdSbGNsOHlNU05qY3lJc0ltZDRPbWhsWVdSeGRXRnlkR1Z5YzBGa1pISmxjM01pT25zaVFHbGtJam9pWlhnNlFXUmtjbVZ6YzE4NU9USWpZM01pZlN3aVozZzZjM1ZpVDNKbllXNXBjMkYwYVc5dVQyWWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbXhsWjJGc1FXUmtjbVZ6Y3lJNmV5SkFhV1FpT2lKbGVEcEJaR1J5WlhOelh6azVNaU5qY3lKOUxDSm5lRHB5WldkcGMzUnlZWFJwYjI1T2RXMWlaWElpT25zaVFHbGtJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbTl5Wnk5emRXSnFaV04wY3k4eE1qTWlmU3dpWjNnNmNHRnlaVzUwVDNKbllXNXBlbUYwYVc5dVQyWWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56UXJNREU2TURBaWZRLnNjRkt1YUtYVF8zbnZ6blhwSHRfQjJkWFktRFNZRldfX2dneW1Xd0E1ZF9HV1VpOER4VzNsZE9ZV0dpeHNHNGJwNkVuOGtWM1dtVjhCaWx5R3JvTU1nIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEJ2YVc1MFQyWlFjbVZ6Wlc1alpTSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcFFiMmx1ZEU5bVVISmxjMlZ1WTJVaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNOQ3N3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2xCdmFXNTBUMlpRY21WelpXNWpaU05qY3lJc0ltZDRPbTkzYm1Wa1Fua2lPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbWx1ZEdWeVkyOXVibVZqZEdWa1VHRnlkR2xqYVhCaGJuUnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHAzWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemN5STZleUpBYVdRaU9pSmxlRHBYWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemMxOHpOak1qWTNNaWZTd2laM2c2YVc1MFpYSmpiMjV1WldOMGFXOXVVRzlwYm5SSlpHVnVkR2xtYVdWeUlqcDdJa0JwWkNJNkltVjRPa2x1ZEdWeVkyOXVibVZqZEdsdmJsQnZhVzUwU1dSbGJuUnBabWxsY2w4Mk1UWWpZM01pZlN3aVozZzZiV0ZwYm5SaGFXNWxaRUo1SWpwN0lrQnBaQ0k2SW1WNE9rbHVkR1Z5Ym1WMFUyVnlkbWxqWlZCeWIzWnBaR1Z5WHpJeEkyTnpJbjBzSW1kNE9tVnVaWEpuZVZWellXZGxSV1ptYVdOcFpXNWplU0k2ZXlKQWFXUWlPaUpsZURwRmJtVnlaM2xWYzJGblpVVm1abWxqYVdWdVkzbGZORGd5STJOekluMHNJbWQ0T20xaGJuVm1ZV04wZFhKbFpFSjVJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHBzYjJOaGRHbHZiaUk2ZXlKQWFXUWlPaUpsZURwQlpHUnlaWE56WHprNU1pTmpjeUo5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLkpzZ2lsaDNrdnZHeGdjb2wxUzRBaVREc2kybFdUakR3RFJhOXdZLUI1clo1OWJpNUVoRkw5bTZ0SUV5QW5BNmttMk1zTDBmaV81cWNObzZDY01nS0hnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbE5sY25acFkyVlBabVpsY21sdVoxUmxjM1FpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2VTJWeWRtbGpaVTltWm1WeWFXNW5JbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpRck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcFRaWEoyYVdObFQyWm1aWEpwYm1kVVpYTjBJMk56SWl3aVozZzZjbVZ4ZFdseVpXUk5aV0Z6ZFhKbGN5STZleUpBYVdRaU9pSmxlRHBOWldGemRYSmxYelUyTlNOamN5SjlMQ0puZURwd2NtOTJhV1JsY2tOdmJuUmhZM1JKYm1admNtMWhkR2x2YmlJNmV5SkFhV1FpT2lKbGVEcERiMjUwWVdOMFNXNW1iM0p0WVhScGIyNWZNakk1STJOekluMHNJbWQ0T210bGVYZHZjbVFpT2lKamNVcHNiM3BLYWlJc0ltZDRPbVJoZEdGUWIzSjBZV0pwYkdsMGVTSTZleUpBYVdRaU9pSmxlRHBFWVhSaFVHOXlkR0ZpYVd4cGRIbGZOemszSTJOekluMHNJbWQ0T21SaGRHRlFjbTkwWldOMGFXOXVVbVZuYVcxbElqb2lURWRRUkRJd01Ua2lMQ0puZURwa1lYUmhRV05qYjNWdWRFVjRjRzl5ZENJNmV5SkFhV1FpT2lKbGVEcEVZWFJoUVdOamIzVnVkRVY0Y0c5eWRGODFNRElqWTNNaWZTd2laM2c2WTNKNWNIUnZaM0poY0docFkxTmxZM1Z5YVhSNVUzUmhibVJoY21Seklqb2lVa1pET1RFME1pSXNJbWQ0T25CeWIzWnBjMmx2YmxSNWNHVWlPaUp3ZFdKc2FXTWlMQ0puZURwc1pXZGhiRVJ2WTNWdFpXNTBjeUk2VzNzaVFHbGtJam9pWlhnNlFXTmpaWE56UTI5dWRISnZiRTFoYm1GblpXMWxiblJmT0RrMUkyTnpJbjBzZXlKQWFXUWlPaUpsZURwQmMzTmxkSE5OWVc1aFoyVnRaVzUwWHpJeU1pTmpjeUo5TEhzaVFHbGtJam9pWlhnNlFuVnphVzVsYzNORGIyNTBhVzUxYVhSNVRXVmhjM1Z5WlhOZk5qUTJJMk56SW4wc2V5SkFhV1FpT2lKbGVEcERhR0Z1WjJWQmJtUkRiMjVtYVdkMWNtRjBhVzl1VFdGdVlXZGxiV1Z1ZEY4MU5qSWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9rTnZiWEJzYVdGdVkyVkJjM04xY21GdVkyVmZPVGMySTJOekluMHNleUpBYVdRaU9pSmxlRHBEYjNCNWNtbG5hSFJCYm1SSmJuUmxiR3hsWTNSMVlXeFFjbTl3WlhKMGVVUnZZM1Z0Wlc1MFh6VTFNeU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZRM1Z6ZEc5dFpYSkJkV1JwZEdsdVoxSnBaMmgwYzE4ME5USWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVJHRjBZVUZqWTJWemMxUmxjbTF6WHprd015TmpjeUo5TEhzaVFHbGtJam9pWlhnNlEzVnpkRzl0WlhKRVlYUmhVSEp2WTJWemMybHVaMVJsY20xelh6VXpNQ05qY3lKOUxIc2lRR2xrSWpvaVpYZzZSR0YwWVZCeWIzUmxZM1JwYjI1U1pXZDFiR0YwYVc5dVRXVmhjM1Z5WlhOZk1URXdJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEVaWFpsYkc5d2JXVnVkRU41WTJ4bFUyVmpkWEpwZEhsZk5qVXhJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEViMk4xYldWdWRFTm9ZVzVuWlZCeWIyTmxaSFZ5WlhOZk5ERTVJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEZiWEJzYjNsbFpWSmxjM0J2Ym5OcFltbHNhWFJwWlhOZk5EY2pZM01pZlN4N0lrQnBaQ0k2SW1WNE9rVnVkbWx5YjI1dFpXNTBZV3hKYlhCaFkzUlNaWEJ2Y25SZk56YzFJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEhiM1psY201dFpXNTBTVzUyWlhOMGFXZGhkR2x2YmsxaGJtRm5aVzFsYm5SZk5qRTVJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEpibVp2Y20xaGRHbHZibE5sWTNWeWFYUjVUM0puWVc1cGVtRjBhVzl1WHpZMU55TmpjeUo5TEhzaVFHbGtJam9pWlhnNlNXNW1iM0p0WVhScGIyNVRaV04xY21sMGVWQnZiR2xqYVdWelh6azNPU05qY3lKOUxIc2lRR2xrSWpvaVpYZzZTVzVtYjNKdFlYUnBiMjVUWldOMWNtbDBlVkpwYzJ0TllXNWhaMlZ0Wlc1MFh6YzJNU05qY3lKOUxIc2lRR2xrSWpvaVpYZzZUR1ZuWVd4c2VVSnBibVJwYm1kQlkzUmZPRE01STJOekluMHNleUpBYVdRaU9pSmxlRHBQY0dWeVlYUnBiMjVoYkZObFkzVnlhWFI1WHpVNE5TTmpjeUo5TEhzaVFHbGtJam9pWlhnNlVHaDVjMmxqWVd4VFpXTjFjbWwwZVY4eE16TWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9sQnliMk4xY21WdFpXNTBUV0Z1WVdkbGJXVnVkRk5sWTNWeWFYUjVYekl3TnlOamN5SjlMSHNpUUdsa0lqb2laWGc2VUhKdlpIVmpkRk5sWTNWeWFYUjVYemd4TlNOamN5SjlMSHNpUUdsa0lqb2laWGc2VW05c1pVRnVaRkpsYzNCdmJuTnBZbWxzYVhScFpYTmZNVE0xSTJOekluMHNleUpBYVdRaU9pSmxlRHBUWldOMWNtbDBlVWx1WTJsa1pXNTBUV0Z1WVdkbGJXVnVkRjh4TVRJalkzTWlmU3g3SWtCcFpDSTZJbVY0T2xObGNuWnBZMlZCWjNKbFpXMWxiblJQWm1abGNsODBOaklqWTNNaWZTeDdJa0JwWkNJNkltVjRPbFZ6WlhKRWIyTjFiV1Z1ZEdGMGFXOXVUV0ZwYm5SbGJtRnVZMlZmT0Rnd0kyTnpJbjFkTENKbmVEcHdiM056YVdKc1pWQmxjbk52Ym1Gc1JHRjBZVlJ5WVc1elptVnljeUk2ZXlKQWFXUWlPaUpsZURwRVlYUmhWSEpoYm5ObVpYSmZNelV4STJOekluMHNJbWQ0T21OMWMzUnZiV1Z5U1c1emRISjFZM1JwYjI1eklqcDdJa0JwWkNJNkltVjRPa04xYzNSdmJXVnlTVzV6ZEhKMVkzUnBiMjV6WHpNeE1DTmpjeUo5TENKbmVEcHdjbTkyYVdSbFpFSjVJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHB6ZFdKRGIyNTBjbUZqZEc5eWN5STZleUpBYVdRaU9pSmxlRHBUZFdKRGIyNTBjbUZqZEc5eVh6YzNNeU5qY3lKOUxDSm5lRHB6WlhKMmFXTmxVRzlzYVdONUlqcDdJa0JwWkNJNkltVjRPbUZqWTJWemMxVnpZV2RsVUc5c2FXTjVJaXdpUUhSNWNHVWlPaUpuZURwQlkyTmxjM05WYzJGblpWQnZiR2xqZVNJc0ltZDRPbkJ2YkdsamVVeGhibWQxWVdkbElqb2lVbVZuYnlJc0ltZDRPbkJ2YkdsamVVUnZZM1Z0Wlc1MElqb2ljR0ZqYTJGblpTQmxlR0Z0Y0d4bFhHNWNibVJsWm1GMWJIUWdZV3hzYjNjZ1BTQm1ZV3h6WlZ4dVhHNWhiR3h2ZHlCN1hHNGdJQ0FnYVc1d2RYUXVkWE5sY2lBOVBTQmhiR2xqWlZ4dUlDQWdJR2x1Y0hWMExtRmpkR2x2YmlBOVBTQnlaV0ZrWEc1OUluMHNJbWQ0T25ObGNuWnBZMlZUWTI5d1pTSTZJbGRQU2xCV1MzcG9JaXdpWjNnNmFHOXpkR1ZrVDI0aU9uc2lRR2xrSWpvaVpYZzZWbWx5ZEhWaGJGSmxjMjkxY21ObFh6VXlJMk56SW4wc0ltZDRPbk5sY25acFkyVlBabVpsY21sdVoxUmxjbTF6UVc1a1EyOXVaR2wwYVc5dWN5STZleUpBYVdRaU9pSmxlRHBVWlhKdGMwRnVaRU52Ym1ScGRHbHZibk5mT0RVeUkyTnpJbjBzSW1kNE9tRm5aM0psWjJGMGFXOXVUMlpTWlhOdmRYSmpaWE1pT2x0N0lrQnBaQ0k2SW1WNE9sSmxjMjkxY21ObFh6TTBPQ05qY3lKOUxIc2lRR2xrSWpvaVpYZzZSR0YwWVVObGJuUmxjaU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZVRzlwYm5SUFpsQnlaWE5sYm1ObEkyTnpJbjFkZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLlB5eXhzT2dvMkZ3ZzBMTUNvRXRDRDc0ZC1LZDU0S2RVbFdMS0ZMX2FqeENCQl9aZWpCdnl6M1JSdVdVejZuQ0hpOHVVbHJJcmV5aDV3bnBycFZpLU13IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbU55WldSbGJuUnBZV3hKYzNOMVpYSWlMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZTWE56ZFdWeUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwamNtVmtaVzUwYVdGc1NYTnpkV1Z5STJOeklpd2laM2c2WjJGcFlYaFVaWEp0YzBGdVpFTnZibVJwZEdsdmJuTWlPaUkwWW1RM05UVTBNRGszTkRRMFl6azJNREk1TW1JME56STJZekpsWm1FeE16Y3pORGcxWlRoaE5UVTJOV1E1TkdRME1URTVOVEl4TkdNMVpUQmpaV0l6SW4wc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM05Dc3dNVG93TUNKOS5PUldXZkk4Y2pybWF1blBDd1hnTmp1amRHU0lGcUd1dHFpLUxKQ1k2bWJlU1dqbmxScmNKNWEwX0txVUxueUZLRkc1RkdVTnltLWx4dkpwdkFtNFFOdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKUVV6STFOaUlzSW1semN5STZJbVJwWkRwM1pXSTZjbVZuYVhOMGNtRjBhVzl1Ym5WdFltVnlMbTV2ZEdGeWVTNXNZV0l1WjJGcFlTMTRMbVYxT25ZeUlpd2lhMmxrSWpvaVpHbGtPbmRsWWpweVpXZHBjM1J5WVhScGIyNXVkVzFpWlhJdWJtOTBZWEo1TG14aFlpNW5ZV2xoTFhndVpYVTZkaklqV0RVd09TMUtWMHNpTENKcFlYUWlPakUzTlRNd09EVXlNRFk0Tnpnc0ltVjRjQ0k2TVRjMk1EZzJNVEl3TmpnM09Td2lZM1I1SWpvaWRtTXJiR1FpTENKMGVYQWlPaUoyWXl0c1pDdHFkM1FpZlEuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2xaaGRFbEVJbDBzSW1sa0lqb2lhSFIwY0hNNkx5OWxlR0Z0Y0d4bExtOXlaeTlqY21Wa1pXNTBhV0ZzY3k4eE1qTWlMQ0p1WVcxbElqb2lWa0ZVSUVsRUlpd2laR1Z6WTNKcGNIUnBiMjRpT2lKV1lXeDFaU0JCWkdSbFpDQlVZWGdnU1dSbGJuUnBabWxsY2lJc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNmNtVm5hWE4wY21GMGFXOXViblZ0WW1WeUxtNXZkR0Z5ZVM1c1lXSXVaMkZwWVMxNExtVjFPbll5SWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF3T0Rvd05qbzBOaTQ0Tnpnck1EQTZNREFpTENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHhPVlF3T0Rvd05qbzBOaTQ0Tnprck1EQTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SnBaQ0k2SW1oMGRIQnpPaTh2WlhoaGJYQnNaUzV2Y21jdmMzVmlhbVZqZEhNdk1USXpJaXdpZEhsd1pTSTZJbWQ0T2xaaGRFbEVJaXdpWjNnNmRtRjBTVVFpT2lKQ1JUQTNOakkzTkRjM01qRWlMQ0puZURwamIzVnVkSEo1UTI5a1pTSTZJa0pGSW4wc0ltVjJhV1JsYm1ObElqcDdJbWQ0T21WMmFXUmxibU5sVDJZaU9pSm5lRHBXWVhSSlJDSXNJbWQ0T21WMmFXUmxibU5sVlZKTUlqb2lhSFIwY0RvdkwyVmpMbVYxY205d1lTNWxkUzkwWVhoaGRHbHZibDlqZFhOMGIyMXpMM1pwWlhNdmMyVnlkbWxqWlhNdlkyaGxZMnRXWVhSVFpYSjJhV05sSWl3aVozZzZaWGhsWTNWMGFXOXVSR0YwWlNJNklqSXdNalV0TURjdE1qRlVNRGc2TURZNk5EWXVPRGMzS3pBd09qQXdJbjE5LmlvR2pjMWhKRXNuZFNpZ1Q5UTYxM3ZEelc4Unk4YTlsOWlaTEppTExZU3VWMmNUc084SVE1eHpydHp3MXJncUd6N1lqODVaR1VPMVhlU2N2YnFlTElLU3F0cENhVVd6UXM1a3pLTkJlaHNsbnJmWG1NUi04Z3VNelhXc1VVc3BsOXR1WnFadk9RckVPa1I2T1J6YXlMU0VyUFdBakNJbXBQTElvOTBnczFIdzcwYlNjM2FDdVExaHFobzl3SGNWS0doVlMtbHg1QzhmQmM0eHNZdjR6MTdCVnFUSzRlcS1nanJxZVdEZmNDTno4cmVUeUZHWjBMM3o2d0hiV21YQ2tDaHByTHI5R1YwanJmRjlxUDIxM2RFM21BWE5FeTNOdkttZkxjWG90SWpwRzNkV295dFZHenVIWHM3c2RzYXRBcGFOUGlDcEZwWmJaREYzbWJuc3pqQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9XSwiaXNzdWVyIjoiZGlkOndlYjpnYWlhLXguZXUiLCJ2YWxpZEZyb20iOiIyMDI1LTA3LTIxVDEwOjIyOjExLjAwMyswMjowMCIsInZhbGlkVW50aWwiOiIyMDI1LTEwLTI5VDEwOjIyOjExLjAwMyswMTowMCJ9.VcPSWoHC6PPUWyXqiUueBA1IPxKhMSqQHzHjjAvA5aAEWYQGvbSukbWWKtmN43Pye7JXLU_GFZE02s8LJQ-1xw";
        // } 

        const isValid = await verifyVpJwt(rawVp, subjectDid, VERIFICATION_METHOD_ID);
        if (!isValid) {
        alert("❌ INTERNAL TEST ----- VP verification failed. Aborting submission.");
        return;
        }

        console.log("[GAIA-X] vcId:", vcId);
        console.log("[GAIA-X] Signed Compliance VP JWT:", rawVp);

        const complianceApiUrl = `${complianceUrlDirect}?vcid=${encodeURIComponent(vcId)}`;

        console.groupCollapsed("[GAIA-X DEBUG] Outgoing Compliance Request");
        console.log("→ Endpoint:", complianceApiUrl);
        console.log("→ Headers:", {
        "Content-Type": "application/vp+jwt",
        "Accept": "application/vc+jwt"
        });
        console.log("→ rawVp (first 300 chars):", rawVp.substring(0, 300) + (rawVp.length > 300 ? "..." : ""));
        console.groupEnd();

        const complianceResponse = await fetch(complianceApiUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/vp+jwt",
            "Accept": "application/vc+jwt"
        },
        body: rawVp  // 🟩 send the VP-JWT directly, NOT JSON-wrapped
        });

            // Client-side error handling for the external API call
        if (!complianceResponse.ok) {
            let errorDetails = `Status: ${complianceResponse.status}`;
            try {
                // Try to parse the error response body
                const data = await complianceResponse.json();
                errorDetails += `, Details: ${JSON.stringify(data)}`;
                console.error('[GAIA-X API Error]', complianceResponse.status, data);
            } catch (e) {
                // Handle non-JSON error responses
                errorDetails += `, Text: ${await complianceResponse.text()}`;
            }
            throw new Error(`GAIA-X Compliance API call failed. ${errorDetails}`);
        }

        // Success: Read the response from the external API
        const complianceVcJwt = await complianceResponse.text();
        console.log("[GAIA-X] Compliance Label JWT VC:", complianceVcJwt);
        // --- END LOG RAW JWT TO DEBUG PANEL ---

        // --- LOG RAW JWT TO DEBUG PANEL (as requested) ---
        // Parse the decodedPayload to get the id of the VC for logging
        //*********** */    // const decodedComplianceVC = decodeJwt(complianceVcJwt); 
        //*********** */    // console.log("[GAIA-X] Decoded Compliance VC:", decodedComplianceVC);
        // --- END LOG RAW JWT TO DEBUG PANEL ---
        
        // Store the received Compliance VC in the VcStore
        storeVc(vcId, complianceVcJwt, VcStore);
        return complianceVcJwt; 

    } catch (error) {
        console.error("[GAIA-X] Compliance VC creation failed:", error);
        throw error;
    }
}

async function requestGaiaxVc(vatId,subjectDid, hqCountryCode) {
    let decodedPayload = null;
    let credentialSubject = null;


    const registrationIdVc = await requestGaiaxRegistrationNumberVc(vatId,subjectDid);
    // Log the raw VC JWT received
    console.log("Raw Registration Number VC JWT:", registrationIdVc);

    if (!registrationIdVc) {
        throw new Error("Failed to obtain Legal Registration Number VC from GAIA-X Notary.");
    }
    // Decode the JWT to extract the credentialSubject
    decodedPayload = decodeJwt(registrationIdVc); 
    const registrationVcId = decodedPayload?.id || "unknown";
    console.log(`✅ Received VC with ID: ${registrationVcId}`);
    console.warn("GAIA-X Decoded Registration Number VC", decodedPayload);
    
    credentialSubject = decodedPayload?.credentialSubject;
    console.warn("GAIA-X Decoded Registration Number VC", decodedPayload);
    
    // Log credentialSubject for debugging
    console.log("Decoded VC Payload:", decodedPayload);
    if (!credentialSubject) {
        console.warn("VC received, but missing 'credentialSubject' in payload.");
        throw new Error("VC received, but missing 'credentialSubject' in payload.");
    }
    const legalAddressCountryCode = credentialSubject["gx:countryCode"] || "";   
    // Log extracted values
    console.warn(`Extracted Legal Address Country Code: ${legalAddressCountryCode}`);

    const termsAndConditionsVc = await selfIssueTermsAndConditionsVc(subjectDid);
    if (!termsAndConditionsVc) {
        console.warn("Failed to obtain Terms & Conditions VC.");
        throw new Error("Failed to obtain Terms & Conditions VC.");
    }

    const legalPersonVc = await selfIssueLegalParticipantVc(subjectDid, hqCountryCode, legalAddressCountryCode);
    if (!legalPersonVc) {
        console.warn("Failed to obtain Legal Person VC.");
        throw new Error("Failed to obtain Legal Person VC.");
    }   
    const dataConsumerVc = await selfIssueDataConsumerVc(subjectDid, hqCountryCode, legalAddressCountryCode);
    if (!dataConsumerVc) {
        console.warn("Failed to obtain Data Consumer VC.");
        throw new Error("Failed to obtain Data Consumer VC.");
    }   
    const issuerVc = await selfIssueIssuerVc(subjectDid);
    if (!issuerVc) {
        console.warn("Failed to obtain Issuer VC.");
        throw new Error("Failed to obtain Issuer VC.");
    }   

    // Log the raw T&C VC JWT received
    console.warn("--------------------->>>>> Raw Terms & Conditions VC JWT:", termsAndConditionsVc); 
    // Log the raw Legal Person VC JWT received
    console.warn("--------------------->>>>> Raw Legal Person VC JWT:", legalPersonVc);
    // Log the raw Data Consumer VC JWT received
    console.warn("--------------------->>>>> Raw Data Consumer VC JWT:", dataConsumerVc);
    // Log the raw Issuer VC JWT received
    console.warn("--------------------->>>>> Raw Issuer VC JWT:", issuerVc);

    const complianceLabelVc = await requestComplianceLabelVc(subjectDid);
    if (!complianceLabelVc) {
        console.warn("Failed to obtain Compliance Label VC.");
        throw new Error("Failed to obtain Compliance Label VC.");
    }
    console.warn("✅ Received Compliance Label VC (JWT):", complianceLabelVc);

    // $$$$$$$ PLACENOTE: To be updated later to return the Compliance Label VC
    return complianceLabelVc;
}

// ====================================================================================
// GAIA-X Step 1:  GET Legal Registration VC from GAIA-X Notary
// ====================================================================================
/**
 * Stores a  Verifiable Credential JWT using its ID as the key.
 * @param {string} vatId - The VAT ID of the organization to be onboarded.
 * @param {string} subjectDid - The DID of the subject (participant organization).
 * @throws {Error} If input validation fails.
 */
async function requestGaiaxRegistrationNumberVc(vatId,subjectDid) {


    const NOTARY_API_BASE = "https://registrationnumber.notary.lab.gaia-x.eu/development/registration-numbers/vat-id/";


    console.log("VAT ID:", vatId, "Subject DID:", subjectDid);
   
    try {
        if (!vatId || !subjectDid) {
            throw new Error("VAT ID and Subject DID must be provided.");
        }
        
        // 1. Construct the API URL
        // Use the global APP_BASE_URL for the VC ID (which is URL based)
        // const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        // const vcId = `${APP_BASE_URL}/credentials/${crypto.randomUUID()}`;
        const vcId = `${APP_BASE_URL}/credentials/registration-number`;

        const apiUrl = new URL(`${NOTARY_API_BASE}${vatId}`);
        apiUrl.searchParams.set('vcId', vcId);
        apiUrl.searchParams.set('subjectId', subjectDid);

        console.log(`Fetching VC from: ${apiUrl.toString()}`);

        // 2. Perform the API Request with required header
        const response = await fetch(apiUrl.toString(), {
            method: 'GET',
            headers: {
                // This header is essential for the Notary to return the JWT VC text
                'accept': 'application/vc+jwt' 
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`API returned status ${response.status}: ${errorText.substring(0, 100)}...`);
        }

        // The response body is the raw VC JWT text
        const rawVc = await response.text();

        console.log("✅ Received Registration Number VC JWT:", rawVc);

        try {
            // 2. Store the VC using the core utility function
            storeVc(vcId, rawVc, VcStore);
            // 3. Log success
            console.log(`[VC STORE] Registration Number VC stored successfully for ID: ${vcId}`);
            return rawVc;
        } catch (error) {
            // 4. HTTP Error Concern: Handle validation errors from the utility function
            console.warn(`[VC STORE] Failed to store VC: ${error.message}`);
        }

    } catch (error) {
        // Error Notification
        console.error("VC Request failed:", error);
    } finally {
        console.warn("GAIA-X Step 1 completed");
    }
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////// END OF UPDATES TO PROVIDE GAIA-X  VC IN THE BACKEND //////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// ====================================================================================
// EXPRESS ROUTE HANDLER: Handles HTTP Request/Response Flow
// ====================================================================================

// ===== API: Store  VC =====
app.post("/api/store-compliance-vc", isAuthenticated, (req, res) => {
    // 1. HTTP Concern: Destructure the required payload from the request body
    const { vcId, complianceVcJwt } = req.body;

    try {
        // 2. Call the core utility function
        // We pass the storage mechanism as an argument (Dependency Injection)
        storeVc(vcId, complianceVcJwt, VcStore);

        // 3. HTTP Response Concern: Respond with success
        res.status(200).json({ success: true, message: "Compliance VC stored successfully." });

    } catch (error) {
        // 4. HTTP Error Concern: Handle validation errors from the utility function
        console.warn(`[VC STORE] Failed to store VC: ${error.message}`);
        // Return 400 Bad Request for validation errors
        return res.status(400).send(error.message);
    }
});

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

// ========================================================
// ===== API: Sign VC (Express Route Handler) ======
// ========================================================
/**
 * Express endpoint to receive a VC payload and return a signed JWT.
 * It handles the HTTP request/response lifecycle.
 */
app.post("/api/sign-vc", async (req, res) => {
    // 1. HTTP Extraction
    const vcPayload = req.body?.vcPayload;

    try {
        // 2. Call the reusable core function
        const signed = await signVcCore(vcPayload);

        // 3. HTTP Response Concern: Send the final signed VC
        res.set("Content-Type", "application/vc+jwt").status(200).send(signed);

    } catch (err) {
        // 4. HTTP Error Concern: Handle and respond to errors based on type
        const message = err?.message || err;
        
        // Use 400 for validation errors thrown by signVcCore
        if (message.includes("Missing") || message.includes("missing")) {
            console.warn(`Validation Error signing VC: ${message}`);
            return res.status(400).send(`Validation error: ${message}`);
        }
        
        // Use 500 for internal errors like key not ready
        console.error("Internal Error signing VC:", err);
        return res.status(500).send(`Internal signing error: ${message}`);
    }
});
// ===== End API: Sign VC =====


// ===== API: Sign VP (JWS/JWT) =====
app.post("/api/sign-vp", async (req, res) => {
    try {
        // 1. HTTP Lifecycle Concern: Wait for signingKey readiness
        // The original code uses a loop for key initialization, which is a good practice here.
        for (let i = 0; i < 20 && !signingKey; ++i) await new Promise(r => setTimeout(r, 90));
        if (!signingKey) {
            console.error("Signing key not ready in /api/sign-vp");
            return res.status(500).send("Signing key not ready");
        }

        const vpPayload = req.body?.vpPayload;

        // 2. HTTP Validation Concern: Check for payload
        if (!vpPayload) {
            return res.status(400).send("Missing vpPayload");
        }

        // 3. Call the core utility function
        const signedVp = await signVerifiablePresentation(
            vpPayload,
            signingKey,
            DID,
            VERIFICATION_METHOD_ID,
            jose
        );

        // 4. HTTP Response Concern: Send the final signed VP
        // Return signed VP-JWT with the correct media type
        res.set("Content-Type", "application/vp+jwt").status(200).send(signedVp);

    } catch (err) {
        // 5. HTTP Error Concern: Handle and respond to errors
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
        // set the kid to the verificationMethodId to the right of the hash i.e. withouth the preceeding path


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
                
            // Protocol must be explicitly included for the URI: https://<domain>
            const x5uUri = `https://${DOMAIN}/.well-known/fullpem/0001_chain.pem`;
            const base64Leaf = leafPem
            .replace(/-----BEGIN CERTIFICATE-----/, "")
            .replace(/-----END CERTIFICATE-----/, "")
            .replace(/\s+/g, "");

            // Set required JWK fields for P-256
            jwk = {
                kty: "EC",
                alg: "ES256",
                kid: kid,
                crv: "P-256", // Standard name for JWK/DID-JWK
                x: jwkResult.x,
                y: jwkResult.y,
                x5u: x5uUri,
                // x5c:[base64Leaf],
                // Include debug info temporarily
                _debug: jwkResult._debug 
            };
            console.log(" Display public key JWK from reading the DID:", JSON.stringify(jwk, null, 2));
            
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
        



        // --- 4. Assemble DID Document ---
        const didDoc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ],
            id: did,
            verificationMethod: [
                {
                    id: verificationMethodId,
                    type: "JsonWebKey2020",
                    controller: did,
                    publicKeyJwk: jwkFinal
                }
            ],
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

// ===== TESTING Express Endpoint for VP Verification =====

app.post("/api/verify-vp", async (req, res) => {
  const vpJwt = req.body?.vpJwt;
  if (!vpJwt) {
    return res.status(400).json({ error: "Missing vpJwt in request body" });
  }

  try {
    console.log("\n🔍 Starting VP JWT verification...");
    const parts = vpJwt.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    const [headerB64, payloadB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));

    console.log("Header:", header);
    console.log("Payload:", payload);

    const issuerDid = DID;
    const kid = VERIFICATION_METHOD_ID;
    if (!issuerDid || !kid) throw new Error("Missing 'iss' or 'kid'");

    console.log(`Issuer DID: ${issuerDid}`);
    console.log(`Key ID (kid): ${kid}`);

    const didUrl = `https://${issuerDid.split(":")[2]}/.well-known/did.json`;
    const didResp = await fetch(didUrl);
    if (!didResp.ok) throw new Error(`Failed to fetch DID document: ${didResp.status}`);
    const didDoc = await didResp.json();

    const verificationMethod = didDoc.verificationMethod?.find(vm => vm.id === kid);
    if (!verificationMethod) throw new Error("Verification method not found in DID document");

    const jwk = verificationMethod.publicKeyJwk;
    if (!jwk) throw new Error("JWK not found in verification method");

    console.log("JWK:", jwk);

    const publicKey = await jose.importJWK(jwk, "ES256");
    const { payload: verifiedPayload } = await jose.jwtVerify(vpJwt, publicKey, {
      algorithms: ["ES256"]
    });

    // LOG THE PUBLIK KEY
    console.log("Public Key FROM THE did used for verification:", publicKey);

    console.log("✅ VP JWT verified successfully.");
    res.json({ success: true, payload: verifiedPayload });
  } catch (err) {
    console.error("❌ VP JWT verification failed:", err.message);
    res.status(400).json({ error: err.message });
  }
});

// =========================================================
// ===== OAUTH2/OIDC & SSE Endpoints =====
// =========================================================

/**
 * 1. Authorization Response Endpoint
 * This receives the OIDC/OAuth2 'code' from the SSI Wallet Agent (via the redirect_uri).
 */
app.get("/auth/direct_post", (req, res) => {
    const { code, state } = req.query;

    console.log("--- Authorization Response Received ---");
    console.log(`[Auth] Code: ${code ? 'RECEIVED' : 'MISSING'}, State: ${state ? 'RECEIVED' : 'MISSING'}`);

    if (!code || !state) {
        // Log the error and redirect back to the app with a simple error message.
        console.error("[Auth] Missing required parameters: code or state.");
        return res.redirect(`/?error=auth_failed`);
    }

    // --- 1. Store the code and status (AUTHENTICATED)
    sseEventStore.set(state, { status: "AUTHENTICATED", code, state });
    console.log(`[Auth] Stored code for state: ${state}. Ready to notify client.`);

    // --- 2. Notify waiting client via SSE
    if (sseClients.has(state)) {
        const clientRes = sseClients.get(state);
        const message = { status: "AUTHENTICATED", message: JSON.stringify({ code, state }) };

        // Send the event to the waiting client
        clientRes.write(`event: message\n`);
        clientRes.write(`data: ${JSON.stringify(message)}\n\n`);
        
        // Clean up immediately after sending the message
        clientRes.end();
        sseClients.delete(state);
        console.log(`[Auth] Client for state ${state} notified and connection closed.`);
    } else {
        // If the client isn't connected yet, the store will hold the event.
        // The client will check the store upon connecting.
        console.log(`[Auth] Client for state ${state} not connected yet. Event is queued.`);
    }

    // --- 3. Final action: Redirect the user's browser back to the main app
    // The Wallet Agent itself will handle the code exchange, so this only needs to
    // redirect the *browser* back to the front-end application's URL.
    res.redirect("/");
});


// ===== API: Resolve VC by ID (VC Resolution Endpoint) =====
/**
 * Handles GET requests to resolve a VC by its ID (the URI).
 * This endpoint should be publicly accessible for VC resolution.
 */
app.get("/credentials/:uuid", (req, res) => {
    const uuid = req.params.uuid;

    if (!uuid) {
        return res.status(400).send("VC UUID is required.");
    }

    try {
        // 1. Construct the full VC ID URI as used for the map key.
        // It relies on the global DOMAIN constant, assuming the APP_BASE_URL is https://${DOMAIN}
        
        // ************* const fullVcId = `https://${DOMAIN}/credentials/${uuid}`;
        
        const fullVcId = `${APP_BASE_URL}/credentials/${uuid}`;
        // Add console log for debugging
        console.log(`[VC RESOLUTION] ------->>> Resolving VC for ID: ${fullVcId}`);

        // 2. Retrieve the Compliance VC JWT from the store
        const complianceVcJwt = VcStore.get(fullVcId);

        if (!complianceVcJwt) {
            console.warn(`[VC RESOLUTION] Compliance VC not found for ID: ${fullVcId}`);
            return res.status(404).send("Verifiable Credential not found at: " + fullVcId);
        }

        // 3. Respond with the VC JWT and the correct content type (application/vc+jwt)
        console.log(`[VC RESOLUTION] Successfully published VC for ID: ${fullVcId}`);
        res.set("Content-Type", "application/vc+jwt").status(200).send(complianceVcJwt);

    } catch (err) {
        console.error(`[VC RESOLUTION ERROR]`, err);
        res.status(500).send(`Error retrieving VC: ${err.message}`);
    }
});

/**
 * 2. SSE Stream Endpoint
 * This allows the client (index.js) to subscribe and wait for an event tied to the state.
 */
app.get("/sse-server/stream-events/:state", (req, res) => {
    const state = req.params.state;
    console.log(`--- SSE Subscription Request ---`);
    console.log(`[SSE] Client connecting for state: ${state}`);

    // Set headers for SSE
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        // --- ADD THESE TWO LINES FOR CORS SUPPORT ---
        'Access-Control-Allow-Origin': '*', 
        'Access-Control-Allow-Credentials': 'true'
    });
    
    // Send a keep-alive comment immediately
    res.write(':ok\n\n');

    // --- 1. Check for pre-existing event (race condition check) ---
    if (sseEventStore.has(state)) {
        const eventData = sseEventStore.get(state);
        const message = { status: eventData.status, message: JSON.stringify({ code: eventData.code, state: eventData.state }) };
        
        // Send the queued event immediately
        res.write(`event: message\n`);
        res.write(`data: ${JSON.stringify(message)}\n\n`);
        
        // Clean up the store and close the connection
        sseEventStore.delete(state);
        console.log(`[SSE] Queued event for state ${state} delivered and store cleared.`);
        return res.end();
    }

    // --- 2. If no pre-existing event, register the client for future events ---
    sseClients.set(state, res);
    console.log(`[SSE] Client registered for state: ${state}. Total clients: ${sseClients.size}`);

    // Set a timeout to remove the client if the connection is closed
    req.on('close', () => {
        console.log(`[SSE] Client disconnected for state: ${state}`);
        sseClients.delete(state);
    });
});


// ===== API: Request GAIA-X Compliance Label VC) =====
// server.js

// ===== API: Request GAIA-X Compliance Label VC (CLEANED) =====
/**
 * @swagger
 * /api/gaiax:
 *   post:
 *     summary: Request GAIA-X Compliance Label VC
 *     description: This endpoint requests a GAIA-X Compliance Label Verifiable Credential (VC) based on the provided parameters.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               vatId:
 *                 type: string
 *                 example: "DE123456789"
 *                 description: The VAT ID of the entity requesting the compliance label.
 *               subjectDid:
 *                 type: string
 *                 example: "did:example:123456789"
 *                 description: The decentralized identifier (DID) of the subject.
 *               hqCountryCode:
 *                 type: string
 *                 example: "DE"
 *                 description: The country code of the headquarters (e.g., 'DE' for Germany).
 *     responses:
 *       200:
 *         description: Successful response containing GAIA-X Compliance VC.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 gaiaxRegNumberVC:
 *                   type: string
 *                   description: The GAIA-X Compliance VC received.
 *       400:
 *         description: Bad Request due to missing required parameters.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Missing required parameters: vatId, subjectDid, or hqCountryCode."
 *       500:
 *         description: Internal Server Error due to an unexpected issue while processing the request.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Failed to obtain GAIA-X Compliance VC"
 */
app.post("/api/gaiax", async (req, res) => {
    // 1. Input Extraction
    const vatId = req.body?.vatId;
    const subjectDid = req.body?.subjectDid;
    const hqCountryCode = req.body?.hqCountryCode;

    // 2. Input Validation
    if (!vatId || !subjectDid || !hqCountryCode) {
        return res.status(400).json({ 
            error: "Missing required parameters: vatId, subjectDid, or hqCountryCode." 
        });
    }

    try {
        // 3. Wait for the asynchronous function to complete
        // Execution will pause here until requestGaiaxVc returns or throws an error.
        const gaiaxRegNumberVC = await requestGaiaxVc(
            vatId,
            subjectDid, 
            hqCountryCode
        );

        console.warn("GAIA-X Compliance VC obtained:", gaiaxRegNumberVC);
        
        // 4. Success Response
        // This is only executed if the await call succeeds.
        return res.status(200).json({  
            gaiaxRegNumberVC // PLACEHODER: to be replaced with actual Compliance Label VC when implemented ****************************
        });

    } catch (error) {
        // 5. Error Response
        // This is only executed if the await call fails.
        console.error("Error in GAIA-X VC request:", error);
        // Ensure you return here to stop execution
        return res.status(500).json({ error: "Failed to obtain GAIA-X Compliance VC", detail: error.message });
    }
    
    // Note: No code should be placed here, as all responses are handled inside try/catch.
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