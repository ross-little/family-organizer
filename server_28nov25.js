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
import { createPublicKey } from "crypto"; // for public key operations

// cookie parser
import cookieParser from "cookie-parser";
// session management
import session from "express-session";
// ===== Express App Initialization (EXISTING) =====
// ... (rest of express setup code)
const app = express();

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


// ===== Configuration =====
const DOMAIN = "family-organizer.onrender.com"; 
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

let DID = `did:web:${DOMAIN}`;  // ✅ consistent
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

async function signVerifiableCredential(vcPayload, signingKey, DID, VERIFICATION_METHOD_ID, jose) {
    // Re-check for critical signing components (although the route handles most of this)
    if (!signingKey || !DID || !VERIFICATION_METHOD_ID) {
        throw new Error("Internal signing configuration is incomplete.");
    }
    
    // --- Logic extracted from the original route handler ---
    
    const now = Math.floor(Date.now() / 1000);

    // issuer: prefer explicit issuer in payload, otherwise use your DID
    const issuer = vcPayload.issuer || DID;

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
 * @param {string} DID - The Issuer/Holder's DID (e.g., did:web:...).
 * @param {string} VERIFICATION_METHOD_ID - The Key ID (kid) that corresponds to a verification method.
 * @param {object} jose - The jose library instance (e.g., from 'jose').
 * @returns {Promise<string>} The signed VP in VP-JWT format.
 */
async function signVerifiablePresentation(vpPayload, signingKey, DID, VERIFICATION_METHOD_ID, jose) {
    // Re-check for critical signing components
    if (!signingKey || !DID || !VERIFICATION_METHOD_ID) {
        throw new Error("Internal signing configuration is incomplete.");
    }
    
    // --- Logic extracted from the original route handler ---

    // Protected header per VP-JWT spec
    const protectedHeader = {
        alg: "ES256",
        typ: "vp+jwt",          // VP-JWT media type
        cty: "vp",              // nested VP media type
        iss: DID,               // issuer is your DID
        kid: VERIFICATION_METHOD_ID
    };

    // Sign the VP exactly as received
    const signedVp = await new jose.SignJWT(vpPayload)
        .setProtectedHeader(protectedHeader)
        .sign(signingKey);

    return signedVp;
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

// ===== GAIA-X VC Operations (Step 2a: Self-Issue T&C VC) =====
async function selfIssueTermsAndConditionsVc(participantDid) {
    
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
        
        tCVcId = vcId; // Save for later use in Legal Participant VC;
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
        const response = await fetch("/api/sign-vc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vcPayload })
        });
        const rawVc = await response.text();
        // Save globally
        return rawVc;

    } catch (error) {
        console.warn("T&C VC self-issue failed:", error);
    } finally {
        console.warn("GAIA-X T&C VC self-issue process completed.");
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
        throw new Error("VC received, but missing 'credentialSubject' in payload.");
    }
    const legalAddressCountryCode = credentialSubject["gx:countryCode"] || "";   
    // Log extracted values
    console.warn(`Extracted Legal Address Country Code: ${legalAddressCountryCode}`);

    const termsAndConditionsVc = await requestGaiaxTermsAndConditionsVc(subjectDid);
    if (!termsAndConditionsVc) {
        throw new Error("Failed to obtain Terms & Conditions VC.");
    }

    // Log the raw T&C VC JWT received
    console.log("--------------------->>>>> Raw Terms & Conditions VC JWT:", termsAndConditionsVc);    


    // $$$$$$$ PLACENOTE: To be updated lkater to return the Compliance Label VC
    return registrationIdVc;
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

// ===== API: Sign VC (JWS/JWT) (EXISTING) =====

app.post("/api/sign-vc", async (req, res) => {
    // 1. HTTP Lifecycle Concern: Wait for signingKey readiness
    for (let i = 0; i < 20 && !signingKey; ++i) await new Promise(r => setTimeout(r, 90));
    if (!signingKey) {
        console.error("Signing key not ready in /api/sign-vc");
        return res.status(500).send("Signing key not ready");
    }

    const vcPayload = req.body?.vcPayload;

    // 2. HTTP Validation Concern: Check for payload and required subject ID
    if (!vcPayload) {
        console.warn("No vcPayload in request body:", req.body);
        return res.status(400).send("Missing vcPayload");
    }
    
    if (!vcPayload.credentialSubject || (!vcPayload.credentialSubject.id && !vcPayload.credentialSubject['@id'])) {
        return res.status(400).send("Missing credentialSubject.id or credentialSubject.@id");
    } 

    try {
        // 3. Call the core utility function
        const signed = await signVerifiableCredential(
            vcPayload,
            signingKey,
            DID,
            VERIFICATION_METHOD_ID,
            jose
        );

        // 4. HTTP Response Concern: Send the final signed VC
        res.set("Content-Type", "application/vc+jwt").status(200).send(signed);

    } catch (err) {
        // 5. HTTP Error Concern: Handle and respond to errors
        console.error("Error signing VC:", err);
        res.status(500).send(`Signing error: ${err?.message || err}`);
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