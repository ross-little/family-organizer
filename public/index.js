// ===== Imports =====
import { generateDidDoc } from "./didDoc.js";

// === NEW GLOBAL CONSTANT ===
// OLD const APP_BASE_URL = "https://family-organizer.onrender.com"; 
const isLocalhost = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";
const APP_BASE_URL = isLocalhost
    ? "http://localhost:3000"   // Local development
    : `https://${window.location.hostname}`; // Use secure HTTPS for remote deployment
// This is used for all self-issued VC IDs and internal URL references.

// When testing locally, change this to: "http://localhost:3000"
// This is used for all self-issued VC IDs and internal URL references.
// Define activateTab in the global scope so showLoginOptions can call it.
const panels = {
    login: document.getElementById("loginPanel"),
    todo: document.getElementById("todoPanel"),
    did: document.getElementById("didPanel"),
    gaiax: document.getElementById("gaiaxPanel"),
};
const tabElements = {}; // Will be populated in DOMContentLoaded

// ===== Global State =====
let currentUser = null;
let currentNonce = null;
let currentSse = null;
let legalRegistrationVcPayload = null; 
let legalParticipantVcPayload = null; 
let gaiaxShapes = null; // To store the fetched SHACL shapes
let termsAndConditionsVcPayload = null; // To store T&C VC payload
let legalAddressCountryCode = null; // To store the country code from legal address
// --- GLOBALS ---
let gaiaxParticipantVcJwt = null;       // Step 2: Participant VC
let gaiaxTermsVcJwt = null;             // Step 1: Self-Issued T&C VC
let complianceVcJwt = null;            // Final Compliance VC
let gaiaxRegistrationVcJwt = null;   // Step 0: Registration VC
let TestVp = false;          // Toggle for using test VPC
let issuerDID =null;               // Issuer DID for VPs

// === VC Proof Constants ===

// app.use(express.static(path.join(__dirname, "public")));

// ===== Utilities =====
/**
 * Converts a Base64Url string to a Uint8Array.
 * Handles padding and character replacement for URL safety.
 * This is crucial for correctly decoding JWT parts (header, payload, signature).
 * @param {string} base64UrlString
 * @returns {Uint8Array}
 */
function base64UrlToUint8Array(base64UrlString) {
    // 1. Convert Base64Url to Base64 (replace - with +, _ with /)
    let base64 = base64UrlString.replace(/-/g, "+").replace(/_/g, "/");

    // 2. Add padding '=' if necessary
    while (base64.length % 4) {
        base64 += "=";
    }

    // 3. Decode Base64 string to binary string using atob
    const binaryString = atob(base64);

    // 4. Convert binary string to Uint8Array
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

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

function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// NOTE: This must be defined globally to be accessible by showLoginOptions()
function activateTab(tab) {
    // CRITICAL CHECK: Ensure elements are initialized before use
    if (!panels.login) {
        // If this runs before DOMContentLoaded completes, something is wrong
        console.error("Attempted to activateTab before DOM was fully loaded/initialized.");
        return; 
    }

    // Deactivate all panels and tabs
    Object.keys(panels).forEach(k => {
        if (panels[k]) panels[k].style.display = "none";
    });
    
    Object.values(tabElements).forEach(t => {
        if (t) t.classList.remove("active");
    });

    // Activate the selected tab and show its panel
    if (panels[tab]) panels[tab].style.display = "block";
    if (tabElements[tab + "Tab"]) tabElements[tab + "Tab"].classList.add("active");
}

// ===== Topbar & profile =====
// ===== Topbar & profile (Updated) =====
// ===== Topbar & profile (Updated with onerror fallback) =====
function showUserProfile(user) {
    if (!user) {
        // Clear the topbar
        const topbar = document.getElementById("topbarUserInfo");
        if (topbar) topbar.innerHTML = "";
        // Cosole log for debugging
        console.log("No User - , cleared topbar.");
        return;
    }

    const { name, email, picture } = user;
    const initialAvatarSrc = picture || "/images/pawn.png";
    const topbar = document.getElementById("topbarUserInfo");
    // Console log for debugging
    console.log("Showing User - Name:", name, "Email:", email, "Picture:", picture);

    if (topbar) {
        topbar.innerHTML = `
            <img id="profileAvatar" src="${initialAvatarSrc}" alt="${name || 'avatar'}">
            <span>${email || name || ''}</span>
        `;

        const avatarElement = document.getElementById("profileAvatar");
        if (avatarElement && picture) {
            avatarElement.onerror = function() {
                console.warn("⚠️ Remote profile picture failed to load. Switching to local pawn.png.");
                this.src = "/images/pawn.png"; 
                this.onerror = null; 
            };
        }
    }
}


// This function needs to be defined where index.js can see it.
function showLoginOptions() {
    // This function must call the global activateTab
    activateTab("login"); 

    // 2. Hide main panels, show the login panel
    //document.getElementById("loginPanel").style.display = "block";
    document.getElementById("todoPanel").style.display = "none";
    document.getElementById("didPanel").style.display = "none";
    document.getElementById("gaiaxPanel").style.display = "none";
    document.getElementById("userEmail").textContent = "";

    // 3. Set the Login tab as active
    activateTab("login"); // Assuming you have an activateTab helper function
    
    // 4. Clear profile picture/name
    showUserProfile(null);
}

// Global Function in index.js
function showMainApp() {
    // 1. CRITICAL: Enable all main application tabs
    const tabsToEnable = ["todoTab", "didTab", "gaiaxTab"];
    tabsToEnable.forEach(id => {
        const tabEl = document.getElementById(id);
        if (tabEl) {
            tabEl.disabled = false;
        }
    });

    // 2. Activate the default post-login tab
    // (Assuming you have a global activateTab() function defined)
    activateTab("todo");

    // 3. Show profile/logout button
    document.getElementById("profile").style.display = "flex";
    document.getElementById("logoutBtn").style.display = "block";
}

// ===== Check Existing Session on Load =====
async function checkExistingSession() {
    try {
        const res = await fetch("/api/session/me", { credentials: "include" });
        if (res.ok) {
            const user = await res.json();
            console.log("Existing session found, logging in automatically.");
            await handlePostLogin(user); // Re-establishes UI state and enables tabs/todos
        } else {
            console.log("No active session found.");
        }
    } catch (e) {
        console.error("Session check failed:", e);
    }
}




// ===== ToDo Backend Operations =====
async function loadTasks() {
    try {
        const res = await fetch("/api/todos");
        return await res.json();
    } catch (err) {
        console.error("Failed to load tasks:", err);
        return [];
    }
}

async function addTask() {
    const inputBox = document.getElementById("myInput");
    const text = inputBox.value.trim();
    if (!text) return;

    try {
        const res = await fetch("/api/todos", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text }),
            credentials: "include" // <-- important
        });

        if (!res.ok) {
            const errText = await res.text();
            console.error("Failed to add task:", res.status, errText);
            return;
        }

        inputBox.value = "";
        showTasks();
    } catch (err) {
        console.error("Error adding task:", err);
    }
}


async function toggleTask(id, currentChecked) {
    await fetch(`/api/todos/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ checked: !currentChecked })
    });
    showTasks();
}

async function deleteTask(id) {
    await fetch(`/api/todos/${id}`, { method: "DELETE" });
    showTasks();
}

// ===== Render Tasks =====
async function showTasks() {
    const listContainer = document.getElementById("todoList");
    if (!listContainer) return;

    listContainer.innerHTML = "";
    const tasks = await loadTasks();

    tasks.forEach(task => {
        const li = document.createElement("li");
        li.className = task.checked ? "checked" : "";
        li.innerHTML = `<span>${task.text}</span><button class="delete-btn">🗑️</button>`;

        li.querySelector("span")?.addEventListener("click", () => toggleTask(task.id, task.checked));
        li.querySelector(".delete-btn")?.addEventListener("click", () => deleteTask(task.id));

        listContainer.appendChild(li);
    });
}

// ===== Google Login =====
// ===== Central post-login helper =====
async function handlePostLogin(user) {
    //currentUser = user;
        // 1. Merge new user data with existing global state (critical for retaining the GSI picture/name)
    // If a property exists in the new 'user' object, it is used; otherwise, the property from 'currentUser' is kept.
    currentUser = { ...currentUser, ...user };
    showUserProfile(currentUser);

    // Enable tabs
    ["todoTab", "didTab", "gaiaxTab"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.disabled = false;
    });

    // Activate the ToDo tab by default
    ["loginTab", "todoTab", "didTab", "gaiaxTab"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.remove("active");
    });
    document.getElementById("todoTab")?.classList.add("active");

    // Show main panel
    document.getElementById("loginPanel").style.display = "none";
    document.getElementById("todoPanel").style.display = "block";

    // --- Create backend session ---
    const loginResp = await fetch("/api/session/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: currentUser }),
        credentials: "include"
    });
    const loginData = await loginResp.json().catch(() => ({}));
    // Log the full response for debugging
    console.log("👤 /api/session/login response:", loginData);
    if (!loginResp.ok) {
        // e.g., if the server returned 400 (Bad Request) or 500 (Internal Error)
        console.error("❌ Failed to establish session on server.");
        
        // Optionally display the error message from the server
        try {
            const errorBody = await loginResp.json();
            console.error("Server Error:", errorBody.message);
            alert(`Login Failed: ${errorBody.message || loginResp.statusText}`);
        } catch (e) {
            alert(`Login Failed: Server returned status ${loginResp.status}`);
        }
        
        // Return without proceeding to the main app
        return;
    }

    // Optional: verify session
    const meResp = await fetch("/api/session/me", { credentials: "include" });
    const meData = await meResp.json().catch(() => ({}));
    console.log("👤 /api/session/me response:", meData);

    // Load tasks after session is confirmed
    showTasks();
}

// ===== Google Sign-In callback =====
window.onSignIn = async (response) => {
    console.log("=== Google Sign-In callback fired! ===");
    console.log("Full response:", response);

    if (!response?.credential) {
        console.warn("⚠️ No credential received. Likely origin/client_id mismatch or blocked request.");
        return;
    }

    try {
        const payload = decodeJwt(response.credential);
        console.log("Decoded JWT payload:", payload);

        const user = {
            id: payload.sub,
            name: payload.name || payload.given_name || "",
            email: payload.email,
            picture: payload.picture || ""
        };

        console.log("Current user object:", user);
        await handlePostLogin(user);

    } catch (err) {
        console.error("Google login error:", err);
    }
};




// ===== SSI Wallet Login =====
async function initiateSsiLogin() {
    const qrModal = document.getElementById("qrCodeModal");
    const qrCodeContainer = document.getElementById("qrCodeModalContainer");
    const qrSpinner = document.getElementById("qrCodeSpinner");
    const qrHeader = document.getElementById("qrHeader");

    if (!qrModal || !qrCodeContainer || !qrSpinner || !qrHeader) return;

    qrModal.style.display = "flex";
    qrHeader.style.display = "block";
    qrSpinner.style.display = "block";
    qrCodeContainer.innerHTML = "";

    currentNonce = crypto.randomUUID();
    const state = crypto.randomUUID();

    const authUrl = new URL("https://uself-issuer-agent.cyclops314.gleeze.com/auth/authorize");
    authUrl.searchParams.set("scope", "openid EmployeeCredential");
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", "https://uself-issuer-agent.cyclops314.gleeze.com");
    authUrl.searchParams.set("redirect_uri", "https://uself-issuer-agent.cyclops314.gleeze.com/direct_post");
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("nonce", currentNonce);
    authUrl.searchParams.set("redirect", "false");

    try {
        const response = await fetch(authUrl, { method: "GET", headers: { "Accept": "application/json" } });
        const rawText = await response.text();
        const requestUri = rawText.startsWith("openid://") ? rawText : JSON.parse(rawText).request_uri;

        new QRCode(qrCodeContainer, {
            text: decodeURIComponent(requestUri),
            width: 200,
            height: 200,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });

        const deepLink = document.createElement("a");
        deepLink.href = requestUri;
        deepLink.textContent = "👉 Open in Wallet App (mobile)";
        deepLink.className = "qr-mobile-link";
        deepLink.target = "_blank";
        deepLink.addEventListener("click", () => { qrModal.style.display = "none"; });
        qrCodeContainer?.appendChild(deepLink);

        qrSpinner.style.display = "none";

        startListeningForLogin(currentNonce);

        document.addEventListener("visibilitychange", () => {
            if (!document.hidden && !currentSse && currentNonce) startListeningForLogin(currentNonce);
        });
        window.addEventListener("focus", () => {
            if (!currentSse && currentNonce) startListeningForLogin(currentNonce);
        });

    } catch (error) {
        console.error("SSI login failed:", error);
        alert("Failed to initiate SSI login.");
        qrModal.style.display = "none";
    }
}

// ===== SSE Listener =====
function startListeningForLogin(nonce) {
    if (currentSse) return;
    const subscribeUrl = `https://uself-issuer-agent.cyclops314.gleeze.com/sse-server/stream-events/${nonce}`;
    const es = new EventSource(subscribeUrl);
    currentSse = es;

    es.onmessage = async (event) => {
        try {
            const message = JSON.parse(event.data);

            // 🔍 Always log the raw message
            console.log("[SSE] Received:", message);

            // Optional: show in debug panel
            const debugBox = document.getElementById("ssiDebug");
            if (debugBox) {
                debugBox.textContent += `\n[${new Date().toISOString()}] ${JSON.stringify(message)}`;
                debugBox.scrollTop = debugBox.scrollHeight;
            }

            // ✅ Still handle login success
            if (message.status === "AUTHENTICATED") {
                handleAuthenticated(message);
            }
        } catch (err) {
            console.error("[SSE] Message parse error:", err, event.data);
        }
    };

    es.onerror = (err) => {
        console.error("[SSE] Connection error:", err);
        es.close();
        currentSse = null;
    };
}


// ===== Handle Authenticated (SSI) =====
async function handleAuthenticated(message) {
    if (currentSse) {
        currentSse.close();
        currentSse = null;
    }

    try {
        const inner = JSON.parse(message.message || "{}");
        const code = inner.code;

        const tokenUrl = new URL("https://uself-issuer-agent.cyclops314.gleeze.com/auth/token");
        tokenUrl.searchParams.set("grant_type", "authorization_code");
        tokenUrl.searchParams.set("client_id", "https://uself-issuer-agent.cyclops314.gleeze.com");
        tokenUrl.searchParams.set("code", code);

        const tokenResp = await fetch(tokenUrl.toString(), {
            method: "POST",
            headers: { Accept: "application/json" },
            body: "" // some APIs require POST body even if empty
        });

        const tokens = await tokenResp.json();
        console.log("🔑 Access token response:", tokens);

        const access = tokens.access_token;
        const decoded = decodeJwt(access);

        const userInfo = decoded.claims?.userInfo || {};
        const email = userInfo.email;
        const first = userInfo.firstName || "";
        const last = userInfo.lastName || "";
        const name = `${first} ${last}`.trim() || userInfo.username || email;
        const id = userInfo.id || email;

        const user = { id, email, name, picture: null };
        console.log("Current SSI user object:", user);

        // Reuse the same post-login function as Google
        await handlePostLogin(user);

        // Close QR modal if open
        document.getElementById("qrCodeModal").style.display = "none";

    } catch (err) {
        console.error("❌ SSI handleAuthenticated error:", err);
    }
}

// ===== GAIA-X VC Operations (Utilities) =====


/**
 * Verifies the signature of a VP JWT (JWS) using the issuer's DID document.
 * Assumes ECDSA P-256 signature and did:web resolution.
 *
 * @param {string} vpJwt - The Verifiable Presentation JWT (JWS).
 * @returns {Promise<boolean>} - True if signature is verified, false otherwise.
 */
async function verifyVpJwt(vpJwt) {
    alert("Starting VP JWT verification... Check console and debug panel for details.");
    const debugBox = document.getElementById("ssiDebug"); // Get the debug box here
    console.log("--- START VP JWT Verification ---");
    console.log(`DEBUG: VP JWT (first 30 chars): ${vpJwt.substring(0, 30)}...`);

    const parts = vpJwt.split(".");

    if (parts.length !== 3) {
        console.error("DEBUG: Step 1 FAILED: Invalid JWT format (must have 3 parts).");
        // Add this to ssiDebug panel if needed too 
        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] ERROR: Invalid JWT format (must have 3 parts).`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }   
        return false;
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    console.log("DEBUG: Step 1 PASSED: JWT split into 3 parts.");
    console.log(`DEBUG: Header B64 (first 10 chars): ${headerB64.substring(0, 10)}...`);
    console.log(`DEBUG: Payload B64 (first 10 chars): ${payloadB64.substring(0, 10)}...`);
    // Add this to ssiDebug panel if needed too 
    if (debugBox) {
        debugBox.textContent += `\n[${new Date().toISOString()}] JWT split into 3 parts successfully.`;

        debugBox.textContent += `\n[${new Date().toISOString()}] Header B64: ${headerB64}`;

        debugBox.textContent += `\n[${new Date().toISOString()}] Payload B64: ${payloadB64}`;
        debugBox.scrollTop = debugBox.scrollHeight;
    }

    let header, payload;

    try {
        // Decode header and payload using Base64URL decoding
        header = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(headerB64)));
        payload = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(payloadB64)));

        console.log("DEBUG: Step 2 PASSED: Header and Payload decoded successfully.");
        console.log("DEBUG: Header content:", header);
        console.log("DEBUG: Payload content (claims):", payload);
        // Add this to ssiDebug panel if needed too 
        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] VP JWT Header: ${JSON.stringify(header)}`;

            debugBox.textContent += `\n[${new Date().toISOString()}] VP JWT Payload: ${JSON.stringify(payload)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }   


    } catch (e) {
        console.error("DEBUG: Step 2 FAILED: Failed to decode or parse JWT header/payload:", e);
        // Add this to ssiDebug panel if needed too 
        const debugBox = document.getElementById("ssiDebug");

        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] ERROR: Failed to decode or parse JWT header/payload: ${e}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

        return false;
    }

    // Standard JWT issuer claim is 'iss'. The original code used 'issuer'.
    const issuerDid = payload.iss || payload.issuer;
    const kid = header.kid;

    console.log(`DEBUG: Extracted Issuer DID: ${issuerDid}`);
    console.log(`DEBUG: Extracted Key ID (kid): ${kid}`);

    if (!issuerDid || !kid) {
        console.error(`DEBUG: Step 3 FAILED: Missing 'iss'/'issuer' (${issuerDid}) or 'kid' (${kid}).`);
        return false;
    }
    console.log("DEBUG: Step 3 PASSED: Issuer DID and kid are present.");

    // 1. DID Resolution (Assuming did:web for host-based resolution)
    if (!issuerDid.startsWith("did:web:")) {
         console.warn(`DEBUG: WARNING: Non-did:web issuer detected: ${issuerDid}. Proceeding with custom did:web resolution logic which might be incorrect.`);
    }

    try {
        // Example: did:web:example.com:path -> https://example.com/path/did.json
        const didIdentifier = issuerDid.substring("did:web:".length);
        // Replace ':' with '/' for path segments as per did:web spec, and append /did.json
        const didDocUrl = `https://${didIdentifier.replace(/:/g, '/')}/did.json`;

        console.log(`DEBUG: Step 4: Resolving DID document from URL: ${didDocUrl}`);
        const didDocResp = await fetch(didDocUrl);
        console.log(`DEBUG: DID Doc Fetch Status: ${didDocResp.status} ${didDocResp.statusText}`);

        if (!didDocResp.ok) {
            console.error(`DEBUG: Step 4 FAILED: Failed to fetch DID document. Status: ${didDocResp.status}`);
            return false;
        }

        const didDoc = await didDocResp.json();
        console.log("DEBUG: Step 4 PASSED: DID Document fetched and parsed successfully.");
        // console.log("DEBUG: DID Document (uncomment to inspect):", didDoc); // Uncomment if the full DID Doc is needed

        // 2. Find Verification Material (JWK)
        const verificationMethod = didDoc.verificationMethod?.find(vm => vm.id === kid);
        const jwk = verificationMethod?.publicKeyJwk;
        
        console.log(`DEBUG: Attempting to find verification method with id: ${kid}`);

        if (!verificationMethod) {
            console.error(`DEBUG: Step 5 FAILED: Verification method not found for kid: ${kid} in DID document.`);
            // Add this to ssiDebug panel if needed too 
            const debugBox = document.getElementById("ssiDebug");
            if (debugBox) {
                debugBox.textContent += `\n[${new Date().toISOString()}] ERROR: Verification method not found for kid: ${kid} in DID document.`;
                debugBox.scrollTop = debugBox.scrollHeight;
            }

            return false;
        }

        if (!jwk) {
            console.error(`DEBUG: Step 5 FAILED: Public Key JWK not found within the matching verification method.`);
            // Add this to ssiDebug panel if needed too 
            const debugBox = document.getElementById("ssiDebug");
            if (debugBox) {
                debugBox.textContent += `\n[${new Date().toISOString()}] ERROR: Public Key JWK not found within the matching verification method.`;
                debugBox.scrollTop = debugBox.scrollHeight;
            }

            return false;
        }
        console.log("DEBUG: Step 5 PASSED: Found matching Verification Method and JWK.");
        console.log("DEBUG: JWK 'crv' (curve) used for import:", jwk.crv); // Inspect the curve
        // Add this to ssiDebug panel if needed too 
        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] Found JWK for verification: ${JSON.stringify(jwk)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }   

        // 3. Import Public Key (Assuming ES256 / ECDSA P-256)
        const publicKey = await crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["verify"]
        );
        console.log("DEBUG: Step 6 PASSED: Public Key imported successfully for ECDSA P-256.");
        // Add this to ssiDebug panel if needed too 
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] Public Key imported successfully for ECDSA P-256.`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }   

        // 4. Prepare Data and Signature
        const signedDataString = `${headerB64}.${payloadB64}`;
        const signedData = new TextEncoder().encode(signedDataString);
        const signatureBytes = base64UrlToUint8Array(signatureB64);

        console.log(`DEBUG: Signed Data String (input to hash, first 30 chars): ${signedDataString.substring(0, 30)}...`);
        console.log(`DEBUG: Signed Data Length (bytes): ${signedData.length}`);
        console.log(`DEBUG: Signature B64 (first 10 chars): ${signatureB64.substring(0, 10)}...`);
        console.log(`DEBUG: Signature Bytes Length: ${signatureBytes.length}`);
        // Add this to ssiDebug panel if needed too 
        if (debugBox) {     
            debugBox.textContent += `\n[${new Date().toISOString()}] Prepared signed data and signature for verification.`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }   

        // 5. Verify Signature
        console.log("DEBUG: Step 7: Executing crypto.subtle.verify...");
        const verified = await crypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            publicKey,
            signatureBytes,
            signedData
        );

        if (!verified) {
            console.error("DEBUG: Step 7 FAILED: JWT signature verification failed (crypto.subtle.verify returned false).");
            // Add this to ssiDebug panel if needed too
            if (debugBox) {
                debugBox.textContent += `\n[${new Date().toISOString()}] ERROR: JWT signature verification failed (crypto.subtle.verify returned false).`;
                debugBox.scrollTop = debugBox.scrollHeight;
            }   
        } else {
            console.log("DEBUG: Step 7 PASSED: JWT signature successfully verified.");
            // Add this to ssiDebug panel if needed too     
            if (debugBox) {
                debugBox.textContent += `\n[${new Date().toISOString()}] SUCCESS: JWT signature successfully verified.`;
                debugBox.scrollTop = debugBox.scrollHeight;
            }   
        }
        console.log("--- END VP JWT Verification ---");

        return verified;
    } catch (err) {
        console.error("DEBUG: Verification process FAILED in the try block (Unhandled Error):", err);
        // Add this to ssiDebug panel if needed too
        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] ERROR: Verification process FAILED in the try block: ${err}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }       
        return false;
    }
}



// ===== GAIA-X UI Field Management =====
function prepopulateGaiaxStep2Fields() {
    // 1. Hide the Legal Address Country Code input container
    // ASSUMPTION: The input and label are wrapped in a container with this ID in index.html.
    const legalCountryContainer = document.getElementById("legalAddressCountryCodeContainer"); 
    if (legalCountryContainer) {
        legalCountryContainer.style.display = 'none';
    }
    
    // 2. Default the Headquarters Address Country Code input
    const hqCountryInput = document.getElementById("hqAddressCountryInput");
    
    // Use the stored legal address country code if available
    if (hqCountryInput && legalAddressCountryCode) {
        hqCountryInput.value = legalAddressCountryCode;
        // Optionally disable it so the user knows it's automatic
        // hqCountryInput.disabled = true; 
    }
}

/**
 * Fetches the GAIA-X Trust Framework SHACL shapes and extracts the 
 * Legal Participant VC template requirements.
 */
async function fetchAndParseGaiaxShapes() {
    // Corrected URL to use the one requested by the user: v1-staging
    const SHAPES_URL = "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#"; 

    console.log("Fetching GAIA-X SHACL shapes from staging registry...");
    try {
        const response = await fetch(SHAPES_URL);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const shapes = await response.json();
        
        console.log("✅ GAIA-X SHACL shapes fetched successfully. Storing data.");
        
        // Return the full JSON object to be processed later
        return shapes; 

    } catch (error) {
        console.error("❌ Failed to fetch or parse GAIA-X shapes:", error);
        
        // Fallback: This is the expected structure based on the Trust Framework documentation
        return { 
            requiredProperties: [
                "gx:termsAndConditions",
                "gx:registrationNumber",
                "gx:headquartersAddress",
                "gx:legalAddress"
            ]
        };
    }
}

// ===== GAIA-X VC Operations (Step 1: Request Legal Registration VC) =====
async function requestGaiaxVc() {
    const NOTARY_API_BASE = "https://registrationnumber.notary.lab.gaia-x.eu/development/registration-numbers/vat-id/";
    const btn = document.getElementById("requestVcBtn");
    const vatId = document.getElementById("vatIdInput").value;

    
    const subjectDid = document.getElementById("subjectIdInput").value;
    const notification = document.getElementById("gaiaxNotification");
    const rawVcDisplay = document.getElementById("rawVcDisplay");
    const decodedVcDisplay = document.getElementById("decodedVcDisplay");
    const vcResponseContainer = document.getElementById("vcResponseContainer");
    const debugBox = document.getElementById("ssiDebug"); // Get the debug box here

  console.log("VAT ID:", vatId, "Subject DID:", subjectDid);
    issuerDID = subjectDid; // Store issuer DID globally for later use in VPs   

  if (!vatId || !subjectDid) {
    alert("Missing input fields in the DOM! Check index.html or panel visibility.");
    return;
  }

    // Reset UI and show loading state
    notification.style.display = "none";
    vcResponseContainer.style.display = "none";
    btn.disabled = true;
    btn.textContent = "Requesting VC from GAIA-X Notary...";

    try {
        if (!vatId || !subjectDid) {
            throw new Error("VAT ID and Subject DID must be provided.");
        }
        
        // 1. Construct the API URL
        // Use the global APP_BASE_URL for the VC ID (which is URL based)
        const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        
        const apiUrl = new URL(`${NOTARY_API_BASE}${vatId}`);
        apiUrl.searchParams.set('vcId', vcId);
        apiUrl.searchParams.set('subjectId', subjectDid);

        console.log(`Fetching VC from: ${apiUrl.toString()}`);
        // Log the request URL to the debug panel
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] GAIA-X Request URL: ${apiUrl.toString()}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

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

        gaiaxRegistrationVcJwt = rawVc; // Store the raw VC JWT globally
        localStorage.setItem("gaiax_registration_vc_jwt", rawVc);

        const decodedPayload = decodeJwt(rawVc); 
                    // --- LOG RAW JWT TO DEBUG PANEL (as requested) ---
        if (debugBox) {
            // Log the raw response, indicating it is the JWT
            const logMessage = `GAIA-X Notary Response (Raw JWT): ${rawVc.substring(0, 15000)}...`;
            debugBox.textContent += `\n[${new Date().toISOString()}] ${logMessage}`;
            // Show in the debug box the decoded payload as well
            debugBox.textContent += `\n[${new Date().toISOString()}] GAIA-X Notary Response (Decoded Payload): ${JSON.stringify(decodedPayload, null, 2)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }
        // -------------------------------------------------
        const credentialSubject = decodedPayload?.credentialSubject;

        if (!credentialSubject) {
            throw new Error("VC received, but missing 'credentialSubject' in payload.");
        }

        // 3. Store the VC Subject, mapping the GAIA-X field to the generic name expected by Step 2
        legalRegistrationVcPayload = {
            id: credentialSubject.id, 
            // The GAIA-X payload uses "gx:vatID", we map it to "legalRegistrationId" for seamless Step 2 integration
            legalRegistrationId: credentialSubject["gx:vatID"] || credentialSubject.vatID,
            rawSubject: credentialSubject
        };

        console.log("Stored Legal Registration VC Subject:", legalRegistrationVcPayload);

        // Success Notification
        notification.textContent = "✅ Legal Registration VC successfully received!";
        notification.className = "notification-success";
        notification.style.display = "block";
        
        // Display VC
        rawVcDisplay.textContent = rawVc;
        decodedVcDisplay.textContent = JSON.stringify(decodedPayload, null, 2);
        vcResponseContainer.style.display = "block";

        // Call prefill function and reveal Step 2 UI
        prefillStep2Inputs(legalRegistrationVcPayload); 

    } catch (error) {
        // Error Notification
        notification.textContent = `❌ Failed to request Legal Registration VC: ${error.message}`;
        notification.className = "notification-error";
        notification.style.display = "block";
        rawVcDisplay.textContent = "Error occurred: " + error.message;
        decodedVcDisplay.textContent = "Error occurred.";
        vcResponseContainer.style.display = "block";
        document.getElementById("step2Content").style.display = "none"; // Hide Step 2 on error
        console.error("VC Request failed:", error);
    } finally {
        btn.disabled = false;
        btn.textContent = "Request Legal Registration VC";
        notification.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'start'      
        });
    }
}

// ===== GAIA-X VC Operations (Utility: Prefill Step 2) =====
function prefillStep2Inputs(vcSubject) {
  const step2Content = document.getElementById("step2Content");
  const selfIssueBtn = document.getElementById("selfIssueBtn");

  if (!step2Content) {
    console.error("❌ Step 2 container (#step2Content) not found in DOM.");
    return;
  }

  // Extract values from VC subject
  const registrationId = vcSubject?.legalRegistrationId || "";
  const subjectDid = vcSubject?.id || "";
  const derivedCountryCode = vcSubject?.rawSubject?.["gx:countryCode"] || "";

  // Helper to safely set input values
  function safeSet(id, value, placeholder) {
    const el = document.getElementById(id);
    if (!el) {
      console.warn(`⚠️ Could not find element #${id} in DOM.`);
      return;
    }
    if (value !== undefined && value !== null) el.value = value;
    if (placeholder) el.placeholder = placeholder;
  }

  // Fill inputs
  safeSet("legalRegIdInput", registrationId);
  safeSet("participantDidInput", subjectDid);
  safeSet("termsAndConditionsInput", "", "e.g., SHA-512 hash of GAIA-X T&C");
  safeSet("hqCountryInput", derivedCountryCode);
  safeSet("legalCountryInput", derivedCountryCode);

  // Show Step 2 container
  step2Content.style.display = "block";

  // Enable button
  if (selfIssueBtn) {
    selfIssueBtn.disabled = false;
  } else {
    console.warn("⚠️ Step 2 button (#selfIssueBtn) not found in DOM.");
  }

  console.log("✅ Step 2 prefilled with:", {
    registrationId,
    subjectDid,
    derivedCountryCode
  });
}

//  GAIA-X next step to create self issued JWT VCs for Terms & Conditions and Legal Participant
// index.js (Place this in the global scope, e.g., after showMainApp)

/**
 * Initiates the self-issue process for the Legal Participant VC and T&C VC.
 * This function likely generates a VC payload, sends it to the server for signing, 
 * and then displays a QR code for the wallet to scan (via a Deferred VC Request).
 */
// Global variables to store previously obtained signed JWTs

// Now define the GAIA-X Compliance VC (Verifiable Presentation)

// index.js (Add this utility function)

// ===== GAIA-X Step Management =====

const toRfc3339WithLocalOffset = (date) => {
    const pad = (n, len = 2) => String(n).padStart(len, '0');

    // Get date/time components in LOCAL time
    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hours = pad(date.getHours());
    const minutes = pad(date.getMinutes());
    const seconds = pad(date.getSeconds());
    const milliseconds = pad(date.getMilliseconds(), 3);

    // Calculate timezone offset (returns difference in minutes from UTC)
    const offsetMinutes = date.getTimezoneOffset(); 
    const sign = offsetMinutes < 0 ? '+' : '-';
    const absOffsetMinutes = Math.abs(offsetMinutes);
    const offsetHours = pad(Math.floor(absOffsetMinutes / 60));
    const offsetMins = pad(absOffsetMinutes % 60);
    const offset = `${sign}${offsetHours}:${offsetMins}`;

    // Combine into the required RFC3339-with-local-offset format
    return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}.${milliseconds}${offset}`;
};

async function gaiaxComplianceVc() {
    if (!gaiaxRegistrationVcJwt || !gaiaxTermsVcJwt || !gaiaxParticipantVcJwt) {
        console.error("Missing one or more required GAIA-X VCs.");
        alert("Please ensure Registration, Terms, and Participant VCs are all available before creating the Compliance VC.");
        return;
    }

    const complianceUrlDirect = "https://compliance.lab.gaia-x.eu/development/api/credential-offers/standard-compliance";
    let vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
    
    // --- DATE FORMAT FIX ---
    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);

    // Construct VP payload
    const vpPayload = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "type": "VerifiablePresentation",
        "verifiableCredential": [
            {
                "@context": "https://www.w3.org/ns/credentials/v2",
                "id": `data:application/vc+jwt,${gaiaxRegistrationVcJwt}`,
                "type": "EnvelopedVerifiableCredential"
            },
            {
                "@context": "https://www.w3.org/ns/credentials/v2",
                "id": `data:application/vc+jwt,${gaiaxTermsVcJwt}`,
                "type": "EnvelopedVerifiableCredential"
            },
            {
                "@context": "https://www.w3.org/ns/credentials/v2",
                "id": `data:application/vc+jwt,${gaiaxParticipantVcJwt}`,
                "type": "EnvelopedVerifiableCredential"
            }
        ],
        "issuer": issuerDID,
        "validFrom": validFrom,
        "validUntil": validUntil
    };

    try {
        // 1️⃣ Sign VP via local signing endpoint
        const signResponse = await fetch("/api/sign-vp", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vpPayload })
        });

        if (!signResponse.ok) {
            throw new Error(`VP signing failed: ${signResponse.statusText}`);
        }
        let rawVp = await signResponse.text();
        

        // OPTIONAL TESTING: Allow user to choose to use a test VP instead of the signed one
        // Add button to give option to continue or to use a test rawVp
        // TestVp = confirm("Do you want to use a test VP instead of the signed one?");   
        // if (TestVp) {
        //    alert("Using test VP for demonstration purposes.");
        //    console.warn("⚠️ Using test VP instead of the generated one (TestVp=true)");
        //    vcId = "https://storage.gaia-x.eu/credential-offers/b3e0a068-4bf8-4796-932e-2fa83043e203";
        //    rawVp = "eyJhbGciOiJFUzI1NiIsInR5cCI6InZwK2p3dCIsImN0eSI6InZwIiwiaXNzIjoiZGlkOndlYjpnYWlhLXguZXUiLCJraWQiOiJkaWQ6d2ViOmdhaWEteC5ldSNrZXktMCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwidHlwZSI6IlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkUVUxVnVhWFJmTnpnaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlIxQlRWVzVwZENKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16WTJLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UjFCVFZXNXBkRjgzT0NOamN5SXNJbWQ0T25ObFkyOXVaSE1pT2pVMkxDSm5lRHB0YVc1MWRHVnpJam8wT0N3aVozZzZaR1ZuY21WbGN5STZORFlzSW1kNE9tUmxZMmx0WVd4eklqcDdJa0IyWVd4MVpTSTZNQzQ0T0N3aVFIUjVjR1VpT2lKNGMyUTZabXh2WVhRaWZYMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTJOaXN3TVRvd01DSjkuSmhrQjlHWGx5VkhBdV9ibmkzcHNRcGY1a2xDVkNZVmlTZjR2Sm5uMmVhWDMtZHFDTVcxaW85aVZOejZtdzM1eEJKVTJ1UENzcU9iTEEtX2hoblJVclEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rZFFVMHh2WTJGMGFXOXVYelUwTXlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwSFVGTk1iMk5oZEdsdmJpSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNelk0S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlIxQlRURzlqWVhScGIyNWZOVFF6STJOeklpd2laM2c2YkdGMGFYUjFaR1VpT25zaVFHbGtJam9pWlhnNlIxQlRWVzVwZEY4M09DTmpjeUo5TENKbmVEcGhiSFJwZEhWa1pTSTZJa3B0UzBaTGEydGFJaXdpWjNnNlkzSnpJam9pUTFKVElpd2laM2c2Ykc5dVoybDBkV1JsSWpwN0lrQnBaQ0k2SW1WNE9rZFFVMVZ1YVhSZk56Z2pZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNMk9Dc3dNVG93TUNKOS5mS2VVM3Q3TWhUQV9DVDJhSy1OdS1yYVlXdUZwdzRsWUJRd0JpaV9xbFc1UzhwOGd5MjVsVHNBajNKemRQcnJ1U3lRUndZNnVOb2FTanJVaUNWRDJtUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaUlzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBNWldkaGJGQmxjbk52YmlKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16WTRLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SWl3aVozZzZiR1ZuWVd4QlpHUnlaWE56SWpwN0lrQnBaQ0k2SW1WNE9rRmtaSEpsYzNOZk9Ua3lJMk56SW4wc0ltZDRPbk4xWWs5eVoyRnVhWE5oZEdsdmJrOW1JanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHB5WldkcGMzUnlZWFJwYjI1T2RXMWlaWElpT25zaVFHbGtJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbTl5Wnk5emRXSnFaV04wY3k4eE1qTWlmU3dpWjNnNmFHVmhaSEYxWVhKMFpYSnpRV1JrY21WemN5STZleUpBYVdRaU9pSmxlRHBCWkdSeVpYTnpYems1TWlOamN5SjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNelk0S3pBeE9qQXdJbjAuNnFNTmZyWVdIM2pQdFd4QkxsdXlEaVQyQ2NPTzNUWjlzTkpVdGU2VzYzcWxPd041Q0hJaEVKYlcyNmFodlhaNzNQNkZ3ZVItYlhkMmZPSThpdWp0cnciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rRmpZMlZ6YzBOdmJuUnliMnhOWVc1aFoyVnRaVzUwWHpnNU5TSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEJZMk5sYzNORGIyNTBjbTlzVFdGdVlXZGxiV1Z1ZENKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16WTRLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UVdOalpYTnpRMjl1ZEhKdmJFMWhibUZuWlcxbGJuUmZPRGsxSTJOeklpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHB0YVcxbFZIbHdaWE1pT2lKaGNIQnNhV05oZEdsdmJpOTJibVF1YUhOc0lpd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lTMUlpTENKbmVEcDFjbXdpT25zaVFIWmhiSFZsSWpvaWFYQm1jem92TDIxNVEwbEVJaXdpUUhSNWNHVWlPaUo0YzJRNllXNTVWVkpKSW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek5qZ3JNREU2TURBaWZRLk9iMXdCN3dIazhTVnhKbFRyNWZjMEhhb1F4QnRPUWJzejRKWTJaNW5lbDlfaW5FSU9LR0FrWDVlTjZETUdqTmwxWmw2dU90TG1mYWdydDhXZmRUTmJ3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa0Z6YzJWMGMwMWhibUZuWlcxbGJuUmZNakl5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tGemMyVjBjMDFoYm1GblpXMWxiblFpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNMk9Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa0Z6YzJWMGMwMWhibUZuWlcxbGJuUmZNakl5STJOeklpd2laM2c2ZFhKc0lqcDdJa0IyWVd4MVpTSTZJbWx3Wm5NNkx5OXRlVU5KUkNJc0lrQjBlWEJsSWpvaWVITmtPbUZ1ZVZWU1NTSjlMQ0puZURwdGFXMWxWSGx3WlhNaU9pSmhjSEJzYVdOaGRHbHZiaTkyYm1RdVpYUnphUzVwY0hSMmNISnZabWxzWlN0NGJXd2lMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpLVFNJc0ltZDRPbWx1ZG05c2RtVmtVR0Z5ZEdsbGN5STZleUpBYVdRaU9pSmxlRHBNWldkaGJGQmxjbk52Ymw4M01USWpZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNMk9Tc3dNVG93TUNKOS5VTkxma0pRWHVyeXl4Y2UtTkt4MU93SHJDUWh1ZlJWbXJjdGxYSVhCWnU4R1UyeDNWeWlXdXlwRG1TbUxiZHBtc2FkNklGVTNzdERwNUdKSThZZjBpZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tKMWMybHVaWE56UTI5dWRHbHVkV2wwZVUxbFlYTjFjbVZ6WHpZME5pSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcENkWE5wYm1WemMwTnZiblJwYm5WcGRIbE5aV0Z6ZFhKbGN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNelk1S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlFuVnphVzVsYzNORGIyNTBhVzUxYVhSNVRXVmhjM1Z5WlhOZk5qUTJJMk56SWl3aVozZzZiV2x0WlZSNWNHVnpJam9pYlhWc2RHbHdZWEowTDNndGJXbDRaV1F0Y21Wd2JHRmpaU0lzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pUlZNaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOamtyTURFNk1EQWlmUS5JdEc5UE1SWUZVMmd2a19PUTI2TklkOHg5V1hEUXRzQTI3ZmE0SFRBMl82TzRmSHNsUER5VVBvdkZid19QWVVNQi11TkJQSFBFRld5QnJvVDh1WGhVZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOb1lXNW5aVUZ1WkVOdmJtWnBaM1Z5WVhScGIyNU5ZVzVoWjJWdFpXNTBYelUyTWlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRGFHRnVaMlZCYm1SRGIyNW1hV2QxY21GMGFXOXVUV0Z1WVdkbGJXVnVkQ0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpZNUt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZRMmhoYm1kbFFXNWtRMjl1Wm1sbmRYSmhkR2x2YmsxaGJtRm5aVzFsYm5SZk5UWXlJMk56SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBwYm5admJIWmxaRkJoY25ScFpYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbTFwYldWVWVYQmxjeUk2SW1Gd2NHeHBZMkYwYVc5dUwzWnVaQzVsY0hKcGJuUnpMbVJoZEdFcmVHMXNJaXdpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pVlZvaWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16WTVLekF4T2pBd0luMC4zRkhIWXBtcnVkbGpvRzVxWV90dWt3QlBEUXpxdk44OG14WklxQWtpQ1FzSUtOWXlzdi1tUURZam9qZ2VvNmlYSmNSVVVFeTYwRkNuc2ctNWxXMThZQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOdmJYQnNhV0Z1WTJWQmMzTjFjbUZ1WTJWZk9UYzJJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPa052YlhCc2FXRnVZMlZCYzNOMWNtRnVZMlVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Dc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa052YlhCc2FXRnVZMlZCYzNOMWNtRnVZMlZmT1RjMkkyTnpJaXdpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pVFZVaUxDSm5lRHBwYm5admJIWmxaRkJoY25ScFpYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPblZ5YkNJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkbTVrTG0xekxXbHRjeUo5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpBck1ERTZNREFpZlEuUGJoWXY2enBnMnFtZVUzNHhnd0VzY09NQ25XNlloYjhXQTRIZ0pBNm9OSVlTVlE0dUJwOEZRZzQ3dWprUlRyRWdnNnZreVJ3NXFaUzk4bTJoZGk1NnciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rTnZjSGx5YVdkb2RFRnVaRWx1ZEdWc2JHVmpkSFZoYkZCeWIzQmxjblI1Ukc5amRXMWxiblJmTlRVeklpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rTnZjSGx5YVdkb2RFRnVaRWx1ZEdWc2JHVmpkSFZoYkZCeWIzQmxjblI1Ukc5amRXMWxiblFpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Dc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa052Y0hseWFXZG9kRUZ1WkVsdWRHVnNiR1ZqZEhWaGJGQnliM0JsY25SNVJHOWpkVzFsYm5SZk5UVXpJMk56SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSlNVeUlzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDNadVpDNXZjR1Z1ZUcxc1ptOXliV0YwY3kxdlptWnBZMlZrYjJOMWJXVnVkQzV3Y21WelpXNTBZWFJwYjI1dGJDNXpiR2xrWlN0NGJXd2lMQ0puZURwcGJuWnZiSFpsWkZCaGNuUnBaWE1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hRWlhKemIyNWZOekV5STJOekluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOekFyTURFNk1EQWlmUS5ET1J4YjlISTh1T2xPR1ljd0Y5ejFlbHpSQXZoemFXeU0yRWlQNWNoRS1maE5mUVJvOEEzMThteUoyWWN5b0VhNGsxTkxhR1YxZzZfQVhrT3JiMUpkQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOMWMzUnZiV1Z5UVhWa2FYUnBibWRTYVdkb2RITmZORFV5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tOMWMzUnZiV1Z5UVhWa2FYUnBibWRTYVdkb2RITWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTUNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVFYVmthWFJwYm1kU2FXZG9kSE5mTkRVeUkyTnpJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5TENKbmVEcHRhVzFsVkhsd1pYTWlPaUpoY0hCc2FXTmhkR2x2Ymk5MmJtUXViM0JsYm5odGJHWnZjbTFoZEhNdGIyWm1hV05sWkc5amRXMWxiblF1Y0hKbGMyVnVkR0YwYVc5dWJXd3VjMnhwWkdWVmNHUmhkR1ZKYm1adkszaHRiQ0lzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pUTBraWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3dLekF4T2pBd0luMC53d2E4OHdEVUZScDNmUEJudk5QREpFMy1DaGZNNlhVdnM2VHUyaGZDZFp6MlctdF9ia0N5TVVCaTZxcmtJc2dqM0xxQ0RkWlhlemwwMTlhcmtmRGxVUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOMWMzUnZiV1Z5UkdGMFlVRmpZMlZ6YzFSbGNtMXpYemt3TXlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRGRYTjBiMjFsY2tSaGRHRkJZMk5sYzNOVVpYSnRjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjd0t6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZRM1Z6ZEc5dFpYSkVZWFJoUVdOalpYTnpWR1Z5YlhOZk9UQXpJMk56SWl3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMbVoxYW1sbWFXeHRMbVppTG1SdlkzVjNiM0pyY3lJc0ltZDRPblZ5YkNJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lUVUVpTENKbmVEcHBiblp2YkhabFpGQmhjblJwWlhNaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4UVpYSnpiMjVmTnpFeUkyTnpJbjE5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpBck1ERTZNREFpZlEua1dZVWdVSGlVUVlqdnZrNnBhYVJSc2VOMnFqZWw0Y0duWk90aVlnRkhQT3VOdlZLREVTWG1aOVhRWUNZUVZtU3NfakdjUkV5bW11aWRkWTMwUk9qNFEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVJHRjBZVkJ5YjJObGMzTnBibWRVWlhKdGMxODFNekFpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UTNWemRHOXRaWEpFWVhSaFVISnZZMlZ6YzJsdVoxUmxjbTF6SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56QXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBEZFhOMGIyMWxja1JoZEdGUWNtOWpaWE56YVc1blZHVnliWE5mTlRNd0kyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwdGFXMWxWSGx3WlhNaU9pSmhjSEJzYVdOaGRHbHZiaTkyYm1RdVkzSjVjSFJ2YldGMGIzSXVkbUYxYkhRaUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkNUeUlzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01Dc3dNVG93TUNKOS5qOGl5ZlJSdlZQeWhhRHRZSDN3ckt0R2tzZDBjUmpCb2k0azJIZVdCcm5ZRWVfbW9wODlnWFo2Nm5lcFlQX0J3aXNvakhzQzBqcXlJRjFMUEtkY1pQdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRlFjbTkwWldOMGFXOXVVbVZuZFd4aGRHbHZiazFsWVhOMWNtVnpYekV4TUNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRVlYUmhVSEp2ZEdWamRHbHZibEpsWjNWc1lYUnBiMjVOWldGemRYSmxjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjd0t6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSR0YwWVZCeWIzUmxZM1JwYjI1U1pXZDFiR0YwYVc5dVRXVmhjM1Z5WlhOZk1URXdJMk56SWl3aVozZzZhVzUyYjJ4MlpXUlFZWEowYVdWeklqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcG5iM1psY201cGJtZE1ZWGREYjNWdWRISnBaWE1pT2lKRFZ5SXNJbWQ0T25WeWJDSTZleUpBZG1Gc2RXVWlPaUpwY0daek9pOHZiWGxEU1VRaUxDSkFkSGx3WlNJNkluaHpaRHBoYm5sVlVra2lmU3dpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2YldWeVoyVXRjR0YwWTJncmFuTnZiaUo5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpBck1ERTZNREFpZlEuZmE3Rmx3VVVwbU82dWFPMVo2QUxmY3VkWU5QSUJNcHRpNDR1V3FJd1hTWWtQb2VtT2pnSXJQNVNZcDBpZEJxQW15NEkyemFxNzJXczhpTlZ1YTNlbUEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rUmxkbVZzYjNCdFpXNTBRM2xqYkdWVFpXTjFjbWwwZVY4Mk5URWlMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZSR1YyWld4dmNHMWxiblJEZVdOc1pWTmxZM1Z5YVhSNUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOekFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwRVpYWmxiRzl3YldWdWRFTjVZMnhsVTJWamRYSnBkSGxmTmpVeEkyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwMWNtd2lPbnNpUUhaaGJIVmxJam9pYVhCbWN6b3ZMMjE1UTBsRUlpd2lRSFI1Y0dVaU9pSjRjMlE2WVc1NVZWSkpJbjBzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDNCbmNDMXphV2R1WVhSMWNtVWlMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpUV2lKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLnAwNXJuVnN3OW5SMGw2VGJDOXFEUnQzd09JMXdMWU84VGFzM0N4ZXc1VDJjMVhOdDJPZElkMnBHNTZhdTFtZFlHOGkxcmNkX2tBNmRUNHAxNFZHVDlnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1J2WTNWdFpXNTBRMmhoYm1kbFVISnZZMlZrZFhKbGMxODBNVGtpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2Ukc5amRXMWxiblJEYUdGdVoyVlFjbTlqWldSMWNtVnpJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpFck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcEViMk4xYldWdWRFTm9ZVzVuWlZCeWIyTmxaSFZ5WlhOZk5ERTVJMk56SWl3aVozZzZaMjkyWlhKdWFXNW5UR0YzUTI5MWJuUnlhV1Z6SWpvaVUwMGlMQ0puZURwMWNtd2lPbnNpUUhaaGJIVmxJam9pYVhCbWN6b3ZMMjE1UTBsRUlpd2lRSFI1Y0dVaU9pSjRjMlE2WVc1NVZWSkpJbjBzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNmJXbHRaVlI1Y0dWeklqb2lhVzFoWjJVdmRtNWtMbVp6ZENKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLndsbVhBX2pIVnJsbmtzUER3R3hoT3lMUng3ekNOUE9PakY4NnRBM1ZZZjZoa2UtNERaTnlWZi1DMzA5d2lEaEF3ek9sQ2JjcHRJSU9INFUtTmt1Qjd3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1Z0Y0d4dmVXVmxVbVZ6Y0c5dWMybGlhV3hwZEdsbGMxODBOeUlzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBGYlhCc2IzbGxaVkpsYzNCdmJuTnBZbWxzYVhScFpYTWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTVNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rVnRjR3h2ZVdWbFVtVnpjRzl1YzJsaWFXeHBkR2xsYzE4ME55TmpjeUlzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDJaaGMzUnpiMkZ3SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkxVaUlzSW1kNE9tbHVkbTlzZG1Wa1VHRnlkR2xsY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmWDBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTVNzd01Ub3dNQ0o5LlRaSXFMd2xJckRFNGsta2k3SlVRbWExajdvVFV3aW9sbVgxTHdXWndXMjBMVlc2bDVSelI0c0lrbU03aHA5dDRvdlVsYnVmWUcyY2Yxa21zQnowRktBIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1Z1ZG1seWIyNXRaVzUwWVd4SmJYQmhZM1JTWlhCdmNuUmZOemMxSWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tWdWRtbHliMjV0Wlc1MFlXeEpiWEJoWTNSU1pYQnZjblFpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa1Z1ZG1seWIyNXRaVzUwWVd4SmJYQmhZM1JTWlhCdmNuUmZOemMxSTJOeklpd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkbTVrTG1OdmJXMXZibk53WVdObElpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkNUU0lzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01Tc3dNVG93TUNKOS5NRm1wa3ZScmZzX1J6OFNtX0dzOFdYNzBJc2JkbFV4b1lWNUFiMWpTTEVlOFVLZElMS0RwdFlDU25INkxPY0lJMFd1b1dFcEdkdHJFZVV2Y0hiazlVUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkdmRtVnlibTFsYm5SSmJuWmxjM1JwWjJGMGFXOXVUV0Z1WVdkbGJXVnVkRjgyTVRraUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlIyOTJaWEp1YldWdWRFbHVkbVZ6ZEdsbllYUnBiMjVOWVc1aFoyVnRaVzUwSWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56RXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBIYjNabGNtNXRaVzUwU1c1MlpYTjBhV2RoZEdsdmJrMWhibUZuWlcxbGJuUmZOakU1STJOeklpd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lUbFVpTENKbmVEcDFjbXdpT25zaVFIWmhiSFZsSWpvaWFYQm1jem92TDIxNVEwbEVJaXdpUUhSNWNHVWlPaUo0YzJRNllXNTVWVkpKSW4wc0ltZDRPbTFwYldWVWVYQmxjeUk2SW1Gd2NHeHBZMkYwYVc5dUwzWnVaQzVuYjI5bmJHVXRaV0Z5ZEdndWEyMTZJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNemN4S3pBeE9qQXdJbjAudU9XWUp4VXZLeVgwUlQ1eV9pUzdpVWpVVmViTng0ZHhGT3VQOHNDY3UzLWM4dk5neDc4NDJOM0dJLUN6bFRlZ3gzYXRCdUVIcGwzMmRWeFZ5dHJub3ciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rbHVabTl5YldGMGFXOXVVMlZqZFhKcGRIbFBjbWRoYm1sNllYUnBiMjVmTmpVM0lpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rbHVabTl5YldGMGFXOXVVMlZqZFhKcGRIbFBjbWRoYm1sNllYUnBiMjRpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa2x1Wm05eWJXRjBhVzl1VTJWamRYSnBkSGxQY21kaGJtbDZZWFJwYjI1Zk5qVTNJMk56SWl3aVozZzZhVzUyYjJ4MlpXUlFZWEowYVdWeklqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcDFjbXdpT25zaVFIWmhiSFZsSWpvaWFYQm1jem92TDIxNVEwbEVJaXdpUUhSNWNHVWlPaUo0YzJRNllXNTVWVkpKSW4wc0ltZDRPbWR2ZG1WeWJtbHVaMHhoZDBOdmRXNTBjbWxsY3lJNklrTllJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2YzJsdGNHeGxMVzFsYzNOaFoyVXRjM1Z0YldGeWVTSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOekVyTURFNk1EQWlmUS4zOFVVZkpzRVk0WGx2YlpleUQwcm1KSnE1TVdZRnhwTm1aN3ItOTE3NU0yQWlqc1hHVTU1dFJUTnVjbEdBVXkwVnBMSDdJZm45bXV0LUpxYmFoN3RHUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tsdVptOXliV0YwYVc5dVUyVmpkWEpwZEhsUWIyeHBZMmxsYzE4NU56a2lMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZTVzVtYjNKdFlYUnBiMjVUWldOMWNtbDBlVkJ2YkdsamFXVnpJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpFck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcEpibVp2Y20xaGRHbHZibE5sWTNWeWFYUjVVRzlzYVdOcFpYTmZPVGM1STJOeklpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSkhUU0lzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlN3aVozZzZiV2x0WlZSNWNHVnpJam9pZG1sa1pXOHZkbTVrTG5KaFpHZGhiV1YwZEc5dmJITXVjMjFoWTJ0bGNpSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOekVyTURFNk1EQWlmUS5ZRksyVG16UG1zdUEtd3kzWExJazF2WHVHUzhuTUlmU194czZqZ0V2cUowSndqVXhFRGdRaFdCTXVRaXJnZDFYaVQyV05fTVlZZXd4UUJHMHNKWEl5QSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tsdVptOXliV0YwYVc5dVUyVmpkWEpwZEhsU2FYTnJUV0Z1WVdkbGJXVnVkRjgzTmpFaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlNXNW1iM0p0WVhScGIyNVRaV04xY21sMGVWSnBjMnROWVc1aFoyVnRaVzUwSWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56RXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBKYm1admNtMWhkR2x2YmxObFkzVnlhWFI1VW1semEwMWhibUZuWlcxbGJuUmZOell4STJOeklpd2laM2c2ZFhKc0lqcDdJa0IyWVd4MVpTSTZJbWx3Wm5NNkx5OXRlVU5KUkNJc0lrQjBlWEJsSWpvaWVITmtPbUZ1ZVZWU1NTSjlMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpUUnlJc0ltZDRPbWx1ZG05c2RtVmtVR0Z5ZEdsbGN5STZleUpBYVdRaU9pSmxlRHBNWldkaGJGQmxjbk52Ymw4M01USWpZM01pZlN3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMak5uY0hBdWJXTjJhV1JsYnkxMVpTMWpiMjVtYVdjcmVHMXNJbjBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTVNzd01Ub3dNQ0o5LlppM2ZSc1pDQUJpU0VPZzl5MGtjNGllWHNYZk9DT1o0bDlPY1U3a3Q2LUtfQXFkdDBMam9DODdrTU9Mcmo5OHBWQ0JGemFjZm52OG12alJVMU5GeEVnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa3hsWjJGc2JIbENhVzVrYVc1blFXTjBYemd6T1NJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwTVpXZGhiR3g1UW1sdVpHbHVaMEZqZENKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16Y3hLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeHNlVUpwYm1ScGJtZEJZM1JmT0RNNUkyTnpJaXdpWjNnNloyOTJaWEp1YVc1blRHRjNRMjkxYm5SeWFXVnpJam9pU1U4aUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMHNJbWQ0T21sdWRtOXNkbVZrVUdGeWRHbGxjeUk2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkbTVrTG1sd2JHUXVZMkZ5SW4wc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01Tc3dNVG93TUNKOS5YazJlTXNsVFRwUnFZcGhnazRLZ0laYlFuV3hhVlBMYWlqNWFDX3V6eWFhTXBWcmFVaW9MWjdCM0ZFa09sUHU5d2tydWY3aDdkbEcwNWhxeUpVWmZRdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2s5d1pYSmhkR2x2Ym1Gc1UyVmpkWEpwZEhsZk5UZzFJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPazl3WlhKaGRHbHZibUZzVTJWamRYSnBkSGtpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPazl3WlhKaGRHbHZibUZzVTJWamRYSnBkSGxmTlRnMUkyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwbmIzWmxjbTVwYm1kTVlYZERiM1Z1ZEhKcFpYTWlPaUpDVGlJc0ltZDRPblZ5YkNJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZNMmR3WkdGemFDMXhiMlV0Y21Wd2IzSjBLM2h0YkNKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLm9FeTYzMl9aVllsTENvNlRNRTc2SERBZWxZV3FUQU9ybUxsMGdMTUFSSEFST1Q3QlVGUzlwSXRGNVpjLWNUSGhvMnNzU1I3QmZEUVZNczk1ajJsYTl3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEJvZVhOcFkyRnNVMlZqZFhKcGRIbGZNVE16SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2xCb2VYTnBZMkZzVTJWamRYSnBkSGtpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01Tc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbEJvZVhOcFkyRnNVMlZqZFhKcGRIbGZNVE16STJOeklpd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lXVlFpTENKbmVEcHBiblp2YkhabFpGQmhjblJwWlhNaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4UVpYSnpiMjVmTnpFeUkyTnpJbjBzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlN3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMbTl3Wlc1NGJXeG1iM0p0WVhSekxXOW1abWxqWldSdlkzVnRaVzUwTG5kdmNtUndjbTlqWlhOemFXNW5iV3d1YzNSNWJHVnpLM2h0YkNKOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56RXJNREU2TURBaWZRLjN2bDBhakdsSjdMemhnU3R5bFZIOUlwRUZRNWxRclZVTUZUU0d5RlJyWko4YWt6MHViWGlIWGVTR3BmZmdreDZBblRQaURuMFBRN2pWY3FFbTk5a3pRIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEJ5YjJOMWNtVnRaVzUwVFdGdVlXZGxiV1Z1ZEZObFkzVnlhWFI1WHpJd055SXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcFFjbTlqZFhKbGJXVnVkRTFoYm1GblpXMWxiblJUWldOMWNtbDBlU0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjeUt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZVSEp2WTNWeVpXMWxiblJOWVc1aFoyVnRaVzUwVTJWamRYSnBkSGxmTWpBM0kyTnpJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5TENKbmVEcHBiblp2YkhabFpGQmhjblJwWlhNaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4UVpYSnpiMjVmTnpFeUkyTnpJbjBzSW1kNE9tMXBiV1ZVZVhCbGN5STZJbUZ3Y0d4cFkyRjBhVzl1TDNadVpDNXBjR3hrTG5KaGR5SXNJbWQ0T21kdmRtVnlibWx1WjB4aGQwTnZkVzUwY21sbGN5STZJa05hSW4wc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01pc3dNVG93TUNKOS56LUtzaGFRQUhXNXhWcUFoNG1keWV4R3RkWVdNay14SWxzZG5JR0Zzb3FhYnJ3THRLOEdFcGZpZFNSbnNWOGM0eVd1SnVvOVlvdnlNYVZxeENBWFFZZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xCeWIyUjFZM1JUWldOMWNtbDBlVjg0TVRVaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlVISnZaSFZqZEZObFkzVnlhWFI1SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56SXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBRY205a2RXTjBVMlZqZFhKcGRIbGZPREUxSTJOeklpd2laM2c2ZFhKc0lqcDdJa0IyWVd4MVpTSTZJbWx3Wm5NNkx5OXRlVU5KUkNJc0lrQjBlWEJsSWpvaWVITmtPbUZ1ZVZWU1NTSjlMQ0puZURwdGFXMWxWSGx3WlhNaU9pSmhjSEJzYVdOaGRHbHZiaTkyYm1RdWJXWnRjQ0lzSW1kNE9tZHZkbVZ5Ym1sdVoweGhkME52ZFc1MGNtbGxjeUk2SWtwRklpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5peHpMS0EtbVFjVXJGZ0xaenpYdFdWakdSOWxjQndmbzBGeUxqMXBkN1RyS0tOc1NfZkxkM0EwM19pSC1ONy1BUEJTd0k5XzFLSFNYMGZWRDYwUE5TdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xKdmJHVkJibVJTWlhOd2IyNXphV0pwYkdsMGFXVnpYekV6TlNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwU2IyeGxRVzVrVW1WemNHOXVjMmxpYVd4cGRHbGxjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjeUt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZVbTlzWlVGdVpGSmxjM0J2Ym5OcFltbHNhWFJwWlhOZk1UTTFJMk56SWl3aVozZzZaMjkyWlhKdWFXNW5UR0YzUTI5MWJuUnlhV1Z6SWpvaVZra2lMQ0puZURwcGJuWnZiSFpsWkZCaGNuUnBaWE1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hRWlhKemIyNWZOekV5STJOekluMHNJbWQ0T20xcGJXVlVlWEJsY3lJNkltRndjR3hwWTJGMGFXOXVMM1p1WkM1cWIyOXpkQzVxYjJSaExXRnlZMmhwZG1VaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOeklyTURFNk1EQWlmUS5ldUFrOTVrYlFCVFRzRi1ZVzc5bGdIQ3B1MWY3RzBKN0VGWG9talJjWTMwbnI2T3MyTkF0bEtmSUdMbFhvZGZ2X2djYXJTaTNhMEhtel9IZDlOV3hrdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xObFkzVnlhWFI1U1c1amFXUmxiblJOWVc1aFoyVnRaVzUwWHpFeE1pSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcFRaV04xY21sMGVVbHVZMmxrWlc1MFRXRnVZV2RsYldWdWRDSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemN5S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlUyVmpkWEpwZEhsSmJtTnBaR1Z1ZEUxaGJtRm5aVzFsYm5SZk1URXlJMk56SWl3aVozZzZiV2x0WlZSNWNHVnpJam9pWVhCd2JHbGpZWFJwYjI0dmRtNWtMbVYwYzJrdWFYQjBkblZsY0hKdlptbHNaU3Q0Yld3aUxDSm5lRHBwYm5admJIWmxaRkJoY25ScFpYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbWR2ZG1WeWJtbHVaMHhoZDBOdmRXNTBjbWxsY3lJNklrMVVJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjeUt6QXhPakF3SW4wLlp1Qm85Vkthem9hejBQUndJZnVwMkJ1MC0tUUtiMzhSc0hhQTUydVZobE5lYnA5Z19kM2Y1b0F2eGNHYVktcjV0ZUEwaWh2TlpnakYtR0JDZV9pSXVnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbE5sY25acFkyVkJaM0psWlcxbGJuUlBabVpsY2w4ME5qSWlMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZVMlZ5ZG1salpVRm5jbVZsYldWdWRFOW1abVZ5SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56SXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBUWlhKMmFXTmxRV2R5WldWdFpXNTBUMlptWlhKZk5EWXlJMk56SWl3aVozZzZkWEpzSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBuYjNabGNtNXBibWRNWVhkRGIzVnVkSEpwWlhNaU9pSlVWQ0lzSW1kNE9tMXBiV1ZVZVhCbGN5STZJblpwWkdWdkwyMWhkSEp2YzJ0aElpd2laM2c2YVc1MmIyeDJaV1JRWVhKMGFXVnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5NS05ya2FnMzM0bXNUTEtCMVBITm51RExtMGFyYWY2dUtCa18xVGlObW1rWXcxdHFKNUVTTmxBb2FqeGxXcXVvcVpsTVhHWktPN3M2dFlKNmVnb1pMdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xWelpYSkViMk4xYldWdWRHRjBhVzl1VFdGcGJuUmxibUZ1WTJWZk9EZ3dJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPbFZ6WlhKRWIyTjFiV1Z1ZEdGMGFXOXVUV0ZwYm5SbGJtRnVZMlVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM01pc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbFZ6WlhKRWIyTjFiV1Z1ZEdGMGFXOXVUV0ZwYm5SbGJtRnVZMlZmT0Rnd0kyTnpJaXdpWjNnNmFXNTJiMngyWldSUVlYSjBhV1Z6SWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzVUdWeWMyOXVYemN4TWlOamN5SjlMQ0puZURwMWNtd2lPbnNpUUhaaGJIVmxJam9pYVhCbWN6b3ZMMjE1UTBsRUlpd2lRSFI1Y0dVaU9pSjRjMlE2WVc1NVZWSkpJbjBzSW1kNE9tZHZkbVZ5Ym1sdVoweGhkME52ZFc1MGNtbGxjeUk2SWxORklpd2laM2c2YldsdFpWUjVjR1Z6SWpvaVlYQndiR2xqWVhScGIyNHZkR0Z0Y0MxaGNHVjRMWFZ3WkdGMFpTMWpiMjVtYVhKdEluMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNaXN3TVRvd01DSjkuNDBQTXljWTlHRWd2SG04ZEdQNEtVMmJaYW1VYU9oQWV1UEZpUmpJTHdpZHpialROM0NOalA5M1lmMkZQTzFfdFRQUHZjRVNmMVFuM05mM3BrN3hLSGciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rMWxZWE4xY21WZk5UWTFJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPazFsWVhOMWNtVWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTWlzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rMWxZWE4xY21WZk5UWTFJMk56SWl3aWFIUjBjSE56WTJobGJXRTZaR1Z6WTNKcGNIUnBiMjRpT2lKVFRFUkpTMFlpTENKbmVEcHNaV2RoYkVSdlkzVnRaVzUwY3lJNlczc2lRR2xrSWpvaVpYZzZRV05qWlhOelEyOXVkSEp2YkUxaGJtRm5aVzFsYm5SZk9EazFJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEJjM05sZEhOTllXNWhaMlZ0Wlc1MFh6SXlNaU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZRblZ6YVc1bGMzTkRiMjUwYVc1MWFYUjVUV1ZoYzNWeVpYTmZOalEySTJOekluMHNleUpBYVdRaU9pSmxlRHBEYUdGdVoyVkJibVJEYjI1bWFXZDFjbUYwYVc5dVRXRnVZV2RsYldWdWRGODFOaklqWTNNaWZTeDdJa0JwWkNJNkltVjRPa052YlhCc2FXRnVZMlZCYzNOMWNtRnVZMlZmT1RjMkkyTnpJbjBzZXlKQWFXUWlPaUpsZURwRGIzQjVjbWxuYUhSQmJtUkpiblJsYkd4bFkzUjFZV3hRY205d1pYSjBlVVJ2WTNWdFpXNTBYelUxTXlOamN5SjlMSHNpUUdsa0lqb2laWGc2UTNWemRHOXRaWEpCZFdScGRHbHVaMUpwWjJoMGMxODBOVElqWTNNaWZTeDdJa0JwWkNJNkltVjRPa04xYzNSdmJXVnlSR0YwWVVGalkyVnpjMVJsY20xelh6a3dNeU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZRM1Z6ZEc5dFpYSkVZWFJoVUhKdlkyVnpjMmx1WjFSbGNtMXpYelV6TUNOamN5SjlMSHNpUUdsa0lqb2laWGc2UkdGMFlWQnliM1JsWTNScGIyNVNaV2QxYkdGMGFXOXVUV1ZoYzNWeVpYTmZNVEV3STJOekluMHNleUpBYVdRaU9pSmxlRHBFWlhabGJHOXdiV1Z1ZEVONVkyeGxVMlZqZFhKcGRIbGZOalV4STJOekluMHNleUpBYVdRaU9pSmxlRHBFYjJOMWJXVnVkRU5vWVc1blpWQnliMk5sWkhWeVpYTmZOREU1STJOekluMHNleUpBYVdRaU9pSmxlRHBGYlhCc2IzbGxaVkpsYzNCdmJuTnBZbWxzYVhScFpYTmZORGNqWTNNaWZTeDdJa0JwWkNJNkltVjRPa1Z1ZG1seWIyNXRaVzUwWVd4SmJYQmhZM1JTWlhCdmNuUmZOemMxSTJOekluMHNleUpBYVdRaU9pSmxlRHBIYjNabGNtNXRaVzUwU1c1MlpYTjBhV2RoZEdsdmJrMWhibUZuWlcxbGJuUmZOakU1STJOekluMHNleUpBYVdRaU9pSmxlRHBKYm1admNtMWhkR2x2YmxObFkzVnlhWFI1VDNKbllXNXBlbUYwYVc5dVh6WTFOeU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZTVzVtYjNKdFlYUnBiMjVUWldOMWNtbDBlVkJ2YkdsamFXVnpYemszT1NOamN5SjlMSHNpUUdsa0lqb2laWGc2U1c1bWIzSnRZWFJwYjI1VFpXTjFjbWwwZVZKcGMydE5ZVzVoWjJWdFpXNTBYemMyTVNOamN5SjlMSHNpUUdsa0lqb2laWGc2VEdWbllXeHNlVUpwYm1ScGJtZEJZM1JmT0RNNUkyTnpJbjBzZXlKQWFXUWlPaUpsZURwUGNHVnlZWFJwYjI1aGJGTmxZM1Z5YVhSNVh6VTROU05qY3lKOUxIc2lRR2xrSWpvaVpYZzZVR2g1YzJsallXeFRaV04xY21sMGVWOHhNek1qWTNNaWZTeDdJa0JwWkNJNkltVjRPbEJ5YjJOMWNtVnRaVzUwVFdGdVlXZGxiV1Z1ZEZObFkzVnlhWFI1WHpJd055TmpjeUo5TEhzaVFHbGtJam9pWlhnNlVISnZaSFZqZEZObFkzVnlhWFI1WHpneE5TTmpjeUo5TEhzaVFHbGtJam9pWlhnNlVtOXNaVUZ1WkZKbGMzQnZibk5wWW1sc2FYUnBaWE5mTVRNMUkyTnpJbjBzZXlKQWFXUWlPaUpsZURwVFpXTjFjbWwwZVVsdVkybGtaVzUwVFdGdVlXZGxiV1Z1ZEY4eE1USWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9sTmxjblpwWTJWQlozSmxaVzFsYm5SUFptWmxjbDgwTmpJalkzTWlmU3g3SWtCcFpDSTZJbVY0T2xWelpYSkViMk4xYldWdWRHRjBhVzl1VFdGcGJuUmxibUZ1WTJWZk9EZ3dJMk56SW4xZGZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5BWkZrVjFZeTZEcDJWNERfdkRWejMyYXc4d3AzeW4wejcwczlvbFNsMGxRSVNBVF9tQlNfZG1NbEZTYXZEd1hIYjI5X3ZtaUtDQ2hadDdrakc2MDloQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tOdmJuUmhZM1JKYm1admNtMWhkR2x2Ymw4eU1qa2lMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZRMjl1ZEdGamRFbHVabTl5YldGMGFXOXVJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpJck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcERiMjUwWVdOMFNXNW1iM0p0WVhScGIyNWZNakk1STJOeklpd2laM2c2WlcxaGFXd2lPaUpoWjA5d2NVaGhZeUlzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM01pc3dNVG93TUNKOS5vc3ktT1VYY283cDkxMU94dHJaeUt2WWdFQVdvQmtGeTFKRHp6S3dsLXRKcXpNbVpqZjN3QUhGWjlRcEQ1UF9DQW1UeEZncDV4UnZOOEhDTUU5T2tEdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNSRzlqZFcxbGJuUmZOREU0SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2t4bFoyRnNSRzlqZFcxbGJuUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTWlzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzUkc5amRXMWxiblJmTkRFNEkyTnpJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2ZG01a0xuQmhkR2xsYm5SbFkyOXRiWE5rYjJNaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMHNJbWQ0T21sdWRtOXNkbVZrVUdGeWRHbGxjeUk2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lRMGtpZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjeUt6QXhPakF3SW4wLnY5S3h5NGlKQjBwbzNnVjQ0d1lsWlhpNkZSLTdBZERTSnlaVm5xSjNLSU5yU2NJNGZRb0dBT0FSWnJETnY5THVhcUJ0anhOQUpFbUJ5RXJGVW1Yd2ZnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1JoZEdGUWIzSjBZV0pwYkdsMGVWODNPVGNpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UkdGMFlWQnZjblJoWW1sc2FYUjVJbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpJck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcEVZWFJoVUc5eWRHRmlhV3hwZEhsZk56azNJMk56SWl3aVozZzZiR1ZuWVd4RWIyTjFiV1Z1ZENJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkVSdlkzVnRaVzUwWHpReE9DTmpjeUo5TENKbmVEcGtiMk4xYldWdWRHRjBhVzl1Y3lJNmV5SkFkbUZzZFdVaU9pSnBjR1p6T2k4dmJYbERTVVFpTENKQWRIbHdaU0k2SW5oelpEcGhibmxWVWtraWZTd2laM2c2WkdWc1pYUnBiMjVOWlhSb2IyUnpJam9pVDFoTlEyTnFWbE1pTENKbmVEcG1iM0p0WVhSeklqb2lXVTVrVW5oR1YyNGlMQ0puZURwd2NtbGphVzVuSWpwN0lrQjJZV3gxWlNJNkltbHdabk02THk5dGVVTkpSQ0lzSWtCMGVYQmxJam9pZUhOa09tRnVlVlZTU1NKOUxDSm5lRHBrWld4bGRHbHZibFJwYldWbWNtRnRaU0k2SW5wNldVVk5jbTEzSWl3aVozZzZiV1ZoYm5NaU9pSk1lbTlIWW1GbVVDSXNJbWQ0T25KbGMyOTFjbU5sSWpvaVYyWlljbXhpYVdzaUxDSm5lRHBqYjI1MFlXTjBTVzVtYjNKdFlYUnBiMjRpT25zaVFHbGtJam9pWlhnNlEyOXVkR0ZqZEVsdVptOXliV0YwYVc5dVh6SXlPU05qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3lLekF4T2pBd0luMC5EYmM0cFBnenJ5VWlzaU1aSm5ydHAzTUVFd1ZZLTZVbG9TZEVuMWRQWGFaeTFpNE1YRkxLMDNyc3puNGZGa3JRY2FIelZoZGRJYVhlcUEtMUJncnFMUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRkJZMk52ZFc1MFJYaHdiM0owWHpVd01pSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEVZWFJoUVdOamIzVnVkRVY0Y0c5eWRDSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemN6S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlJHRjBZVUZqWTI5MWJuUkZlSEJ2Y25SZk5UQXlJMk56SWl3aVozZzZabTl5YldGMFZIbHdaU0k2SW1Gd2NHeHBZMkYwYVc5dUwyTmpZMlY0SWl3aVozZzZjbVZ4ZFdWemRGUjVjR1VpT2lKQlVFa2lMQ0puZURwaFkyTmxjM05VZVhCbElqb2laR2xuYVhSaGJDSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOek1yTURFNk1EQWlmUS5lM3owVDZ6VXZrTkVsNEROOE85NTRjQURIWHM3Vy1kbWxzOW1xNS1xa1c0ZG1NSmVmc3FaTmN3V2xiUVpTWi1vLXB0TlFfYVhHVzE1RmVyT3NLV2NIUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRlVjbUZ1YzJabGNsOHpOVEVpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UkdGMFlWUnlZVzV6Wm1WeUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOek1yTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwRVlYUmhWSEpoYm5ObVpYSmZNelV4STJOeklpd2laM2c2YzJOdmNHVWlPaUpOYVZSaVZVMVZieUlzSW1kNE9uSmxZWE52YmlJNkluSnFRWGRZUkhWcEluMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNeXN3TVRvd01DSjkualF3aDl2MGhUZm9zT0E4NHdOT2E1WTAxM2Nzc25tZS1hbUxBaGxfUFlWdGdjdnpRSEFEbDJTazdjcVpjUzE1QzZiNFVoUGl2V2hFOEEtTDdkb3JkaGciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVNXNXpkSEoxWTNScGIyNXpYek14TUNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwRGRYTjBiMjFsY2tsdWMzUnlkV04wYVc5dWN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemN6S3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlEzVnpkRzl0WlhKSmJuTjBjblZqZEdsdmJuTmZNekV3STJOeklpd2laM2c2ZEdWeWJYTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeEViMk4xYldWdWRGODBNVGdqWTNNaWZTd2laM2c2YldWaGJuTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeEViMk4xYldWdWRGODBNVGdqWTNNaWZYMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNeXN3TVRvd01DSjkuUFB3NDJmUGVWMEoyZkZjcnBOWVNxdkhMOFI0blhieldXNFEwVnpqblo5ZFByM1dUdWR6dnhmZEoxc2VZdjhSbEhXQzRBSGFfc2V2aFlVUjBabmVJVlEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9sTjFZa052Ym5SeVlXTjBiM0pmTnpjeklpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9sTjFZa052Ym5SeVlXTjBiM0lpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM015c3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbE4xWWtOdmJuUnlZV04wYjNKZk56Y3pJMk56SWl3aVozZzZZMjl0YlhWdWFXTmhkR2x2YmsxbGRHaHZaSE1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hFYjJOMWJXVnVkRjgwTVRnalkzTWlmU3dpWjNnNmJHVm5ZV3hPWVcxbElqb2lWRmh4UlhaaFdWa2lMQ0puZURwaGNIQnNhV05oWW14bFNuVnlhWE5rYVdOMGFXOXVJam9pVkZJaUxDSm5lRHBwYm1admNtMWhkR2x2YmtSdlkzVnRaVzUwY3lJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkVSdlkzVnRaVzUwWHpReE9DTmpjeUo5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjekt6QXhPakF3SW4wLl9BSmdkeDhSLVA3NlBWc3VvRXJSQklEVnlEeGtad2ZKOGFlRW0wUmUxTTZiYXYzVk92S1NzcHFXSGZkN3RVSUZfVGJ6VlNjMWlyV2dNSlJjY0pDS25nIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEpsYzI5MWNtTmxYek0wT0NJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwU1pYTnZkWEpqWlNKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16Y3pLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2VW1WemIzVnlZMlZmTXpRNEkyTnpJaXdpWjNnNllXZG5jbVZuWVhScGIyNVBabEpsYzI5MWNtTmxjeUk2ZXlKQWFXUWlPaUpsZURwU1pYTnZkWEpqWlY4ek5EZ2pZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM015c3dNVG93TUNKOS5XSy1QVlU5ek94UWhFRFJrUjRrNURDVVp2ZmVWMWpoVmhPbG5PUERaSkI1YVhwUDlVLXVFZWZrTXM3elhPYVdna1M0eEozWC1QMGNMSngzeG05LVBwZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xacGNuUjFZV3hTWlhOdmRYSmpaVjgxTWlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwV2FYSjBkV0ZzVW1WemIzVnlZMlVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM015c3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPbFpwY25SMVlXeFNaWE52ZFhKalpWODFNaU5qY3lJc0ltZDRPbXhwWTJWdWMyVWlPaUpVVDFKUlZVVXRNUzR4SWl3aVozZzZZMjl3ZVhKcFoyaDBUM2R1WldSQ2VTSTZleUpBYVdRaU9pSmxlRHBNWldkaGJGQmxjbk52Ymw4M01USWpZM01pZlN3aVozZzZjbVZ6YjNWeVkyVlFiMnhwWTNraU9pSlJUV1ZrVTJkMVlpSXNJbWQ0T21GblozSmxaMkYwYVc5dVQyWlNaWE52ZFhKalpYTWlPbnNpUUdsa0lqb2laWGc2VW1WemIzVnlZMlZmTXpRNEkyTnpJbjE5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpNck1ERTZNREFpZlEuY09pSnllajlBc2xZei1CRjZDTGtFaFBsSnhSeFptWXh5VkNLMXhmTFpKU1pZZEpUWk5PNGZPeVBsWGhiRlRSZ2dwYXB3UjFjbEF0Y3REYTlGR0FxVWciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9sUmxjbTF6UVc1a1EyOXVaR2wwYVc5dWMxODROVElpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2VkdWeWJYTkJibVJEYjI1a2FYUnBiMjV6SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56TXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBVWlhKdGMwRnVaRU52Ym1ScGRHbHZibk5mT0RVeUkyTnpJaXdpWjNnNmRYSnNJanA3SWtCMllXeDFaU0k2SW1sd1puTTZMeTl0ZVVOSlJDSXNJa0IwZVhCbElqb2llSE5rT21GdWVWVlNTU0o5TENKbmVEcG9ZWE5vSWpvaVMxZDVVMGhPVlVjaWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3pLekF4T2pBd0luMC5US3BNcVljZmotMFVxQ0dOalZVd0ZpRTAyajIycXFXQWRuUlZ6Q2lZX2QtUW1SUllMZzVmRGRlZGI3WWk5WlZDYVU2VVJTNmpoX3Q2RnBLSm11bUdnQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkUVUxVnVhWFJmTWpBNUlpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rZFFVMVZ1YVhRaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNNeXN3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2tkUVUxVnVhWFJmTWpBNUkyTnpJaXdpWjNnNmMyVmpiMjVrY3lJNk5Ea3NJbWQ0T20xcGJuVjBaWE1pT2pJMUxDSm5lRHBrWldkeVpXVnpJam90T1Rrc0ltZDRPbVJsWTJsdFlXeHpJanA3SWtCMllXeDFaU0k2TUM0eU9Td2lRSFI1Y0dVaU9pSjRjMlE2Wm14dllYUWlmWDBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTXlzd01Ub3dNQ0o5LjB1cFNEeEhGYjdYYXRzSmhuV19mZzFTTGNORlRvNHJJZ2ZMYXBFcHNyX3E3QnJ3b1hBcG5MLXNOMGFrLUotY2VicGxaZUxTQVI2OWx0b0EwTnQ0TEFnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa2RRVTB4dlkyRjBhVzl1WHpVeE1DSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEhVRk5NYjJOaGRHbHZiaUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSMUJUVEc5allYUnBiMjVmTlRFd0kyTnpJaXdpWjNnNmJHRjBhWFIxWkdVaU9uc2lRR2xrSWpvaVpYZzZSMUJUVlc1cGRGOHlNRGtqWTNNaWZTd2laM2c2WVd4MGFYUjFaR1VpT2lKNVVWbGhUV1ZsWlNJc0ltZDRPbU55Y3lJNklrTlNVeUlzSW1kNE9teHZibWRwZEhWa1pTSTZleUpBYVdRaU9pSmxlRHBIVUZOVmJtbDBYekl3T1NOamN5SjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNemN6S3pBeE9qQXdJbjAuT3R5T1JBZkkxaHRaWE1Md0FHSFljZEFFV0FNeU1qbUdScVRLdGUwWkRjWG5ldjhrYkU5MWtNYWdOUHhQRlNGSkNIWk5Fa2FhNTJlT1JjaUpXWGtEZVEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rVnVaWEpuZVUxcGVGOHlNRGdpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2Ulc1bGNtZDVUV2w0SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56TXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBGYm1WeVozbE5hWGhmTWpBNEkyTnpJaXdpWjNnNmNtVnVaWGRoWW14bFJXNWxjbWQ1SWpwN0lrQjJZV3gxWlNJNk1pNDJOeXdpUUhSNWNHVWlPaUo0YzJRNlpteHZZWFFpZlN3aVozZzZZWFIwWVdsdWJXVnVkRVJoZEdVaU9uc2lRSFpoYkhWbElqb2lNakF5TlMweE1DMHdOQ0lzSWtCMGVYQmxJam9pZUhOa09tUmhkR1VpZlN3aVozZzZhRzkxY214NVEyRnlZbTl1Um5KbFpVVnVaWEpuZVNJNmV5SkFkbUZzZFdVaU9qSXVOakVzSWtCMGVYQmxJam9pZUhOa09tWnNiMkYwSW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56TXJNREU2TURBaWZRLkQ5STNkZWNOUmNxSVRmZXRuMkR1QUVXME1HeVk5VnNlNS1wUkVVQl9WT2xUcFZuUzZ3WURDOEpVZkxSdWxTMDh3Vm43U0NydHdBR1VzdEI1Q3ozV0t3IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa2RRVTFWdWFYUmZNVFFpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2UjFCVFZXNXBkQ0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSMUJUVlc1cGRGOHhOQ05qY3lJc0ltZDRPbk5sWTI5dVpITWlPak13TENKbmVEcHRhVzUxZEdWeklqbzBNeXdpWjNnNlpHVm5jbVZsY3lJNkxUa3dMQ0puZURwa1pXTnBiV0ZzY3lJNmV5SkFkbUZzZFdVaU9qQXVOVFFzSWtCMGVYQmxJam9pZUhOa09tWnNiMkYwSW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56TXJNREU2TURBaWZRLjRwN1JKTFNyb2VkcjRTVlUwNmRGcmFxVDgzNlBYQTFNTzlsNVhVTVJGaUJsZTdrQWlWRGNXbkE4bkphV3RxWjIyUF9JekJTUktwMXJvOFQ2dHZKUW93IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa2RRVTB4dlkyRjBhVzl1WHpNek9TSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcEhVRk5NYjJOaGRHbHZiaUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZSMUJUVEc5allYUnBiMjVmTXpNNUkyTnpJaXdpWjNnNmJHRjBhWFIxWkdVaU9uc2lRR2xrSWpvaVpYZzZSMUJUVlc1cGRGOHhOQ05qY3lKOUxDSm5lRHBoYkhScGRIVmtaU0k2SW1ac1FYZFNXVTlwSWl3aVozZzZZM0p6SWpvaVExSlRJaXdpWjNnNmJHOXVaMmwwZFdSbElqcDdJa0JwWkNJNkltVjRPa2RRVTFWdWFYUmZNVFFqWTNNaWZYMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNNeXN3TVRvd01DSjkubkI3VGE5eXI1N2FYU3JsWmNmVWtjdmU5X2tsYUxta3dNZ2l6eS1CWkdyTzkzdXFUMm54ZWp0bEQ5d2lxUGxWdXdZRjd0N2dhcWxWZWViYjg1UUtRQmciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9sSmxjMjkxY21ObFh6STRPQ0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBTWlhOdmRYSmpaU0pkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjekt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZVbVZ6YjNWeVkyVmZNamc0STJOeklpd2laM2c2WVdkbmNtVm5ZWFJwYjI1UFpsSmxjMjkxY21ObGN5STZleUpBYVdRaU9pSmxlRHBTWlhOdmRYSmpaVjh5T0RnalkzTWlmWDBzSW5aaGJHbGtWVzUwYVd3aU9pSXlNREkxTFRFd0xUSTVWREV3T2pJd09qTXhMak0zTXlzd01Ub3dNQ0o5LlBQaVVXVjNaT3VYQWFDQkp0ZUp3UlVGbjJGZXZfQjJ4UmE1bmRaRk1qb1BWZ0dIaGhWSXRKZ21pZFUzNldteDVrcGU0UlFwSUl0SUZNOGhhUTMyMkxBIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa0YyWVdsc1lXSnBiR2wwZVZwdmJtVmZPRFl6SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tGMllXbHNZV0pwYkdsMGVWcHZibVVpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM015c3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa0YyWVdsc1lXSnBiR2wwZVZwdmJtVmZPRFl6STJOeklpd2laM2c2WVdSa2NtVnpjeUk2ZXlKQWFXUWlPaUpsZURwQlpHUnlaWE56WHprNU1pTmpjeUo5TENKbmVEcGhaMmR5WldkaGRHbHZiazltVW1WemIzVnlZMlZ6SWpwN0lrQnBaQ0k2SW1WNE9sSmxjMjkxY21ObFh6STRPQ05qY3lKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16Y3pLekF4T2pBd0luMC5lcmVFMUdFZGRLSmRJbjR5Tm5sS1I1SVdmSW1kU0pxeVd1RmpXMGo3THEydzI1Y0o4UlRmeTVIR2JMNmNLOVc4UWczZUs1aGdRUC1vWWZOU2htWG9ZUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNSRzlqZFcxbGJuUmZNVE00SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2t4bFoyRnNSRzlqZFcxbGJuUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTXlzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzUkc5amRXMWxiblJmTVRNNEkyTnpJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2ZG01a0xtUmhkR0ZzYjJjaUxDSm5lRHAxY213aU9uc2lRSFpoYkhWbElqb2lhWEJtY3pvdkwyMTVRMGxFSWl3aVFIUjVjR1VpT2lKNGMyUTZZVzU1VlZKSkluMHNJbWQ0T21sdWRtOXNkbVZrVUdGeWRHbGxjeUk2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2WjI5MlpYSnVhVzVuVEdGM1EyOTFiblJ5YVdWeklqb2lSRW9pZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjekt6QXhPakF3SW4wLmZJalNLMDZscUFSQjJBXzdnN2xpUWFYN0JHRG0zSGNKQlpyS3N0T21tNy1Ea1k3akFIMEpDRm1rdzJkWXdWU1puTHRFVU1iYzJGU1MyOVdLc1VQYlVnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbGRoZEdWeVZYTmhaMlZGWm1abFkzUnBkbVZ1WlhOelh6YzVPQ0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBYWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemN5SmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemMwS3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlYyRjBaWEpWYzJGblpVVm1abVZqZEdsMlpXNWxjM05mTnprNEkyTnpJaXdpWjNnNlkyVnlkR2xtYVdOaGRHbHZibk1pT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hFYjJOMWJXVnVkRjh4TXpnalkzTWlmU3dpWjNnNmQyRjBaWEpWYzJGblpVVm1abVZqZEdsMlpXNWxjM01pT25zaVFIWmhiSFZsSWpveUxqWXpMQ0pBZEhsd1pTSTZJbmh6WkRwbWJHOWhkQ0o5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLnVZaVdhQzlXVm1Nb3ItNmNvTTU5Zmp5bU5aOUFwREIzQVhtYmg4RXpHN0RqZXh2OEVkbzlvSFA0bGFXMUMwQ09RbFkwUmJ4RWdPdl9DZF9FSTY1SkRBIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa1Z1WlhKbmVWVnpZV2RsUldabWFXTnBaVzVqZVY4ek5qZ2lMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZSVzVsY21kNVZYTmhaMlZGWm1acFkybGxibU41SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56UXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBGYm1WeVozbFZjMkZuWlVWbVptbGphV1Z1WTNsZk16WTRJMk56SWl3aVozZzZZMlZ5ZEdsbWFXTmhkR2x2Ym5NaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4RWIyTjFiV1Z1ZEY4eE16Z2pZM01pZlN3aVozZzZjRzkzWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNNaU9uc2lRSFpoYkhWbElqb3hMamd4TENKQWRIbHdaU0k2SW5oelpEcG1iRzloZENKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16YzBLekF4T2pBd0luMC45QzVBWDhzcU40S0dMS3AwVjJVLXd1WjhVenZ6Szlyb1Jlc0xWY3ljU0RnYkFBUmU0eDI4N25XTk4yQXU5NVdaSEtURjVOdlM5alBVckdwVjF0MG95QSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRkRaVzUwWlhJaUxDSjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJaXdpWjNnNlJHRjBZV05sYm5SbGNpSmRMQ0pwYzNOMVpYSWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU0lzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TURjdE1qRlVNVEE2TWpBNk16RXVNemMwS3pBeU9qQXdJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaVFHbGtJam9pWlhnNlJHRjBZVU5sYm5SbGNpTmpjeUlzSW1kNE9tVnVaWEpuZVUxcGVDSTZleUpBYVdRaU9pSmxlRHBGYm1WeVozbE5hWGhmTWpBNEkyTnpJbjBzSW1kNE9tRm5aM0psWjJGMGFXOXVUMlpTWlhOdmRYSmpaWE1pT25zaVFHbGtJam9pWlhnNlFYWmhhV3hoWW1sc2FYUjVXbTl1WlY4NE5qTWpZM01pZlN3aVozZzZkMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNNaU9uc2lRR2xrSWpvaVpYZzZWMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNOZk56azRJMk56SW4wc0ltZDRPbTFoYVc1MFlXbHVaV1JDZVNJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNmJXRnVkV1poWTNSMWNtVmtRbmtpT25zaVFHbGtJam9pWlhnNlRHVm5ZV3hRWlhKemIyNWZOekV5STJOekluMHNJbWQ0T214dlkyRjBhVzl1SWpwN0lrQnBaQ0k2SW1WNE9rRmtaSEpsYzNOZk9Ua3lJMk56SW4wc0ltZDRPbTkzYm1Wa1Fua2lPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbVZ1WlhKbmVWVnpZV2RsUldabWFXTnBaVzVqZVNJNmV5SkFhV1FpT2lKbGVEcEZibVZ5WjNsVmMyRm5aVVZtWm1samFXVnVZM2xmTXpZNEkyTnpJbjE5TENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHlPVlF4TURveU1Eb3pNUzR6TnpRck1ERTZNREFpZlEuTlZMUV9XVUstdFhiS2NOSk5nMlc0UFNZd1FlbFFJV204RURGOGtIUGtqOV9aSzF5cDNWUTdsaVNMOG9OSVR4QlFyeHVqdWc5MW4wZ3VIa3NIU2VQTXciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rZFFVMVZ1YVhSZk9Ea3hJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0ltZDRPa2RRVTFWdWFYUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTkNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9rZFFVMVZ1YVhSZk9Ea3hJMk56SWl3aVozZzZjMlZqYjI1a2N5STZORGdzSW1kNE9tUmxaM0psWlhNaU9qRXlNU3dpWjNnNlpHVmphVzFoYkhNaU9uc2lRSFpoYkhWbElqb3dMamd6TENKQWRIbHdaU0k2SW5oelpEcG1iRzloZENKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16YzBLekF4T2pBd0luMC5ZYVJJS2llTGhid2NrUXZId1Y1SXA0RFg2ajNPWVBHcUt3Xy1MUnZFTmhxVVZyVW1WTHNJWGNueXVvek1Ub0Fqb0pETjE5RHVLQnlxUU9ES0luZVVDZyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tkUVUweHZZMkYwYVc5dVh6ZzVOeUlzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBIVUZOTWIyTmhkR2x2YmlKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16YzBLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UjFCVFRHOWpZWFJwYjI1Zk9EazNJMk56SWl3aVozZzZiR0YwYVhSMVpHVWlPbnNpUUdsa0lqb2laWGc2UjFCVFZXNXBkRjg0T1RFalkzTWlmU3dpWjNnNllXeDBhWFIxWkdVaU9pSjFkRTFEYW1wdWVTSXNJbWQ0T21OeWN5STZJa05TVXlJc0ltZDRPbXh2Ym1kcGRIVmtaU0k2ZXlKQWFXUWlPaUpsZURwSFVGTlZibWwwWHpnNU1TTmpjeUo5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLkU3RnhOX0NrRl9Gbm9ZVFp1UnI3bVJnVnhoZTh3T21Jakp5YUsxSXpidGJDbjRKQ0R2N2s2VC1DUlhYSEozRlVBRjdKNmpYUzRSTWRfQzFVNkF0cU13IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPa0ZrWkhKbGMzTmZPVGt5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tGa1pISmxjM01pWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSjJZV3hwWkVaeWIyMGlPaUl5TURJMUxUQTNMVEl4VkRFd09qSXdPak14TGpNM05Dc3dNam93TUNJc0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJa0JwWkNJNkltVjRPa0ZrWkhKbGMzTmZPVGt5STJOeklpd2laM2c2WTI5MWJuUnllVU52WkdVaU9pSkhWU0lzSW1kNE9tZHdjeUk2ZXlKQWFXUWlPaUpsZURwSFVGTk1iMk5oZEdsdmJsODRPVGNqWTNNaWZTd2laM2c2WTI5MWJuUnllVTVoYldVaU9pSmFSMk55UmxoUFZpSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS4xcjVZdWdBbkttNmRmNVhjNERHMk9jb1daczFnZHcyaXduald1eWtPVmhUUkFoMlRlT05SSm5Ndnh3ZUlDQmZQV2pvaXFkS04yMUZHOW1INHFUX1hCQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2t4bFoyRnNSRzlqZFcxbGJuUmZOVFEzSWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2t4bFoyRnNSRzlqZFcxbGJuUWlYU3dpYVhOemRXVnlJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKMllXeHBaRVp5YjIwaU9pSXlNREkxTFRBM0xUSXhWREV3T2pJd09qTXhMak0zTkNzd01qb3dNQ0lzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0lrQnBaQ0k2SW1WNE9reGxaMkZzUkc5amRXMWxiblJmTlRRM0kyTnpJaXdpWjNnNmJXbHRaVlI1Y0dWeklqb2lZWEJ3YkdsallYUnBiMjR2YkdRcmFuTnZiaUlzSW1kNE9uVnliQ0k2ZXlKQWRtRnNkV1VpT2lKcGNHWnpPaTh2YlhsRFNVUWlMQ0pBZEhsd1pTSTZJbmh6WkRwaGJubFZVa2tpZlN3aVozZzZhVzUyYjJ4MlpXUlFZWEowYVdWeklqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcG5iM1psY201cGJtZE1ZWGREYjNWdWRISnBaWE1pT2lKVVRDSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS5VeXRxaE1YTEN1VE1PQ2pnZG83Q2UxREU1c0NTSDNPVERqRTNrS1lWaWx6Q090LTJfd3NIeFpMVjI3UGdQVUE4TFdtLWo0S2RvOWppVl9sNUx5a2l1USIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xkaGRHVnlWWE5oWjJWRlptWmxZM1JwZG1WdVpYTnpYek0yTXlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0puZURwWFlYUmxjbFZ6WVdkbFJXWm1aV04wYVhabGJtVnpjeUpkTENKcGMzTjFaWElpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNJc0luWmhiR2xrUm5KdmJTSTZJakl3TWpVdE1EY3RNakZVTVRBNk1qQTZNekV1TXpjMEt6QXlPakF3SWl3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lRR2xrSWpvaVpYZzZWMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNOZk16WXpJMk56SWl3aVozZzZZMlZ5ZEdsbWFXTmhkR2x2Ym5NaU9uc2lRR2xrSWpvaVpYZzZUR1ZuWVd4RWIyTjFiV1Z1ZEY4MU5EY2pZM01pZlN3aVozZzZkMkYwWlhKVmMyRm5aVVZtWm1WamRHbDJaVzVsYzNNaU9uc2lRSFpoYkhWbElqb3lMakExTENKQWRIbHdaU0k2SW5oelpEcG1iRzloZENKOWZTd2lkbUZzYVdSVmJuUnBiQ0k2SWpJd01qVXRNVEF0TWpsVU1UQTZNakE2TXpFdU16YzBLekF4T2pBd0luMC5aSXJ1eHA1T29Ta0E5ZjNNRG1GYjJ5NkhKQzVOZFgxOGN6X21ubEx2MUliUlV3TExIbk9Xemo4Um5McDFpWGpNMWctaXI0eXZubVlJWDdZRk0wWlVDQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2xKbGMyOTFjbU5sWHpJeUlpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9sSmxjMjkxY21ObElsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwU1pYTnZkWEpqWlY4eU1pTmpjeUlzSW1kNE9tRm5aM0psWjJGMGFXOXVUMlpTWlhOdmRYSmpaWE1pT25zaVFHbGtJam9pWlhnNlVtVnpiM1Z5WTJWZk1qSWpZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM05Dc3dNVG93TUNKOS4zMjduN2ZjQTJEZ0I0ZC1uR1lVNkFFUzFkbk1hcno1RUJrZzcxaE1KVzdhWVY0eHFzSUhiQ3JkM2RBSF8zQ21faHZ2ZjFOc2tNdnpuQ05vVzk5LVNYQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tGMllXbHNZV0pwYkdsMGVWcHZibVZmTnpJMklpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rRjJZV2xzWVdKcGJHbDBlVnB2Ym1VaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNOQ3N3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2tGMllXbHNZV0pwYkdsMGVWcHZibVZmTnpJMkkyTnpJaXdpWjNnNllXUmtjbVZ6Y3lJNmV5SkFhV1FpT2lKbGVEcEJaR1J5WlhOelh6azVNaU5qY3lKOUxDSm5lRHBoWjJkeVpXZGhkR2x2Yms5bVVtVnpiM1Z5WTJWeklqcDdJa0JwWkNJNkltVjRPbEpsYzI5MWNtTmxYekl5STJOekluMTlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS56VDZCcUFJN1lwazRDOWUxdGRXelBTcFlXVjVwZmRlU3o4bXlSSjE3NFBPMXp5WVFEbmtNNVpJRE5kb2FxTjhrZmtiZ2ZZeFpGRVFvV2lqLUJSc3BjQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tWdVpYSm5lVlZ6WVdkbFJXWm1hV05wWlc1amVWODBPRElpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2Ulc1bGNtZDVWWE5oWjJWRlptWnBZMmxsYm1ONUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwRmJtVnlaM2xWYzJGblpVVm1abWxqYVdWdVkzbGZORGd5STJOeklpd2laM2c2WTJWeWRHbG1hV05oZEdsdmJuTWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeEViMk4xYldWdWRGODFORGNqWTNNaWZTd2laM2c2Y0c5M1pYSlZjMkZuWlVWbVptVmpkR2wyWlc1bGMzTWlPbnNpUUhaaGJIVmxJam94TGpJMkxDSkFkSGx3WlNJNkluaHpaRHBtYkc5aGRDSjlmU3dpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRBdE1qbFVNVEE2TWpBNk16RXVNemMwS3pBeE9qQXdJbjAuNzRrTzEzdS1CcS1vU2xiZEFOZE1uRTBySmphM215TGt6Nm90TU4wdFlsMk9nYkVNMFNJRFE5QXVNQ0FXY0xfTVNJcXR4Q24yZjYtamkxV1FhUzR1ZFEiLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rUmhkR0ZqWlc1MFpYSmZPVGt5SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2tSaGRHRmpaVzUwWlhJaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNOQ3N3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2tSaGRHRmpaVzUwWlhKZk9Ua3lJMk56SWl3aVozZzZaVzVsY21kNVRXbDRJanA3SWtCcFpDSTZJbVY0T2tWdVpYSm5lVTFwZUY4eU1EZ2pZM01pZlN3aVozZzZZV2RuY21WbllYUnBiMjVQWmxKbGMyOTFjbU5sY3lJNmV5SkFhV1FpT2lKbGVEcEJkbUZwYkdGaWFXeHBkSGxhYjI1bFh6Y3lOaU5qY3lKOUxDSm5lRHAzWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemN5STZleUpBYVdRaU9pSmxlRHBYWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemMxOHpOak1qWTNNaWZTd2laM2c2YldGcGJuUmhhVzVsWkVKNUlqcDdJa0JwWkNJNkltVjRPa3hsWjJGc1VHVnljMjl1WHpjeE1pTmpjeUo5TENKbmVEcHRZVzUxWm1GamRIVnlaV1JDZVNJNmV5SkFhV1FpT2lKbGVEcE1aV2RoYkZCbGNuTnZibDgzTVRJalkzTWlmU3dpWjNnNmJHOWpZWFJwYjI0aU9uc2lRR2xrSWpvaVpYZzZRV1JrY21WemMxODVPVElqWTNNaWZTd2laM2c2YjNkdVpXUkNlU0k2ZXlKQWFXUWlPaUpsZURwTVpXZGhiRkJsY25OdmJsODNNVElqWTNNaWZTd2laM2c2Wlc1bGNtZDVWWE5oWjJWRlptWnBZMmxsYm1ONUlqcDdJa0JwWkNJNkltVjRPa1Z1WlhKbmVWVnpZV2RsUldabWFXTnBaVzVqZVY4ME9ESWpZM01pZlgwc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM05Dc3dNVG93TUNKOS5aSjVSLU9VaFA2WElObHJ6LUpzQWRrOUkwUFdObzNYSG9aYjJwQXdEaDVHdnowQ2hSUlhjRG50RmlmQ0luam9JODJMYTl4NVZoeHNOMVVrMk4xZEJBUSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tSaGRHRmpaVzUwWlhKQmJHeHZZMkYwYVc5dVh6WXpPQ0lzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSm5lRHBFWVhSaFkyVnVkR1Z5UVd4c2IyTmhkR2x2YmlKZExDSnBjM04xWlhJaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTSXNJblpoYkdsa1JuSnZiU0k2SWpJd01qVXRNRGN0TWpGVU1UQTZNakE2TXpFdU16YzBLekF5T2pBd0lpd2lZM0psWkdWdWRHbGhiRk4xWW1wbFkzUWlPbnNpUUdsa0lqb2laWGc2UkdGMFlXTmxiblJsY2tGc2JHOWpZWFJwYjI1Zk5qTTRJMk56SWl3aVozZzZjRzl5ZEU1MWJXSmxjaUk2TVN3aVozZzZjbVZtWlhKelZHOGlPbnNpUUdsa0lqb2laWGc2UkdGMFlXTmxiblJsY2w4NU9USWpZM01pZlN3aVozZzZabXh2YjNJaU9pSlpSRWhXYzJSVlR5SXNJbWQ0T25CaGRHTm9VR0Z1Wld3aU9pSkdkMU5CUW1adGN5SXNJbWQ0T25KaFkydE9kVzFpWlhJaU9pSjJWVU5RWTJWQllTSjlMQ0oyWVd4cFpGVnVkR2xzSWpvaU1qQXlOUzB4TUMweU9WUXhNRG95TURvek1TNHpOelFyTURFNk1EQWlmUS5STndadmdEemV0emJLVDRNdnlnZGtneWdDZFIxcldYN0lfVEpuZkJ2UUdKaVpJaGoxeC0waXlIanFrZm9HYnBJUWhOYlkwV3prQkZqMUtDY1JRQ3d4QSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKRlV6STFOaUlzSW5SNWNDSTZJblpqSzJwM2RDSXNJbU4wZVNJNkluWmpJaXdpYVhOeklqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0pyYVdRaU9pSmthV1E2ZDJWaU9tZGhhV0V0ZUM1bGRTTnJaWGt0TUNKOS5leUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdmJuTXZZM0psWkdWdWRHbGhiSE12ZGpJaUxDSm9kSFJ3Y3pvdkwzY3phV1F1YjNKbkwyZGhhV0V0ZUM5a1pYWmxiRzl3YldWdWRDTWlMSHNpWlhnaU9pSm9kSFJ3T2k4dlpYaGhiWEJzWlM1dmNtY2lmVjBzSWtCcFpDSTZJbVY0T2tsdWRHVnlZMjl1Ym1WamRHbHZibEJ2YVc1MFNXUmxiblJwWm1sbGNsODJNVFlpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2U1c1MFpYSmpiMjV1WldOMGFXOXVVRzlwYm5SSlpHVnVkR2xtYVdWeUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwSmJuUmxjbU52Ym01bFkzUnBiMjVRYjJsdWRFbGtaVzUwYVdacFpYSmZOakUySTJOeklpd2laM2c2YldGalFXUmtjbVZ6Y3lJNklqRXhPbU5sT2poa09qVm1Pa1prT2tJd0lpd2laM2c2YVhCQlpHUnlaWE56SWpvaU1qSXVOalV1TXpFd0xqUWlMQ0puZURwamIyMXdiR1YwWlVsUVNTSTZJazlwWW5SdmNsRldJaXdpWjNnNlpHRjBZV05sYm5SbGNrRnNiRzlqWVhScGIyNGlPbnNpUUdsa0lqb2laWGc2UkdGMFlXTmxiblJsY2tGc2JHOWpZWFJwYjI1Zk5qTTRJMk56SW4wc0ltZDRPbWx3YVZSNWNHVWlPaUpNYVc1cklpd2laM2c2YVhCcFVISnZkbWxrWlhJaU9pSm1jV1pPWmtwWFNpSXNJbWQ0T25Od1pXTnBabWxqVUdGeVlXMWxkR1Z5Y3lJNklrTlRWMVJQV21aekluMHNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV3TFRJNVZERXdPakl3T2pNeExqTTNOQ3N3TVRvd01DSjkuTFg0dE9JZHRzYlNfcVNMdnQ1eW9xSk5rTDVOcmRrbmRHUVhvZVNsQW45OGNZYU1WZTQ3dktrX01CeE1OUGpnUVVLRkN1VEFXS2FIcTdFY2xaU3p0MXciLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifSx7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK2p3dCxleUpoYkdjaU9pSkZVekkxTmlJc0luUjVjQ0k2SW5aaksycDNkQ0lzSW1OMGVTSTZJblpqSWl3aWFYTnpJam9pWkdsa09uZGxZanBuWVdsaExYZ3VaWFVpTENKcmFXUWlPaUprYVdRNmQyVmlPbWRoYVdFdGVDNWxkU05yWlhrdE1DSjkuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pTEhzaVpYZ2lPaUpvZEhSd09pOHZaWGhoYlhCc1pTNXZjbWNpZlYwc0lrQnBaQ0k2SW1WNE9rbHVkR1Z5Ym1WMFUyVnlkbWxqWlZCeWIzWnBaR1Z5WHpJeElpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSW1kNE9rbHVkR1Z5Ym1WMFUyVnlkbWxqWlZCeWIzWnBaR1Z5SWwwc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNloyRnBZUzE0TG1WMUlpd2lkbUZzYVdSR2NtOXRJam9pTWpBeU5TMHdOeTB5TVZReE1Eb3lNRG96TVM0ek56UXJNREk2TURBaUxDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpBYVdRaU9pSmxlRHBKYm5SbGNtNWxkRk5sY25acFkyVlFjbTkyYVdSbGNsOHlNU05qY3lJc0ltZDRPbWhsWVdSeGRXRnlkR1Z5YzBGa1pISmxjM01pT25zaVFHbGtJam9pWlhnNlFXUmtjbVZ6YzE4NU9USWpZM01pZlN3aVozZzZjM1ZpVDNKbllXNXBjMkYwYVc5dVQyWWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbXhsWjJGc1FXUmtjbVZ6Y3lJNmV5SkFhV1FpT2lKbGVEcEJaR1J5WlhOelh6azVNaU5qY3lKOUxDSm5lRHB5WldkcGMzUnlZWFJwYjI1T2RXMWlaWElpT25zaVFHbGtJam9pYUhSMGNITTZMeTlsZUdGdGNHeGxMbTl5Wnk5emRXSnFaV04wY3k4eE1qTWlmU3dpWjNnNmNHRnlaVzUwVDNKbllXNXBlbUYwYVc5dVQyWWlPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4xOUxDSjJZV3hwWkZWdWRHbHNJam9pTWpBeU5TMHhNQzB5T1ZReE1Eb3lNRG96TVM0ek56UXJNREU2TURBaWZRLnNjRkt1YUtYVF8zbnZ6blhwSHRfQjJkWFktRFNZRldfX2dneW1Xd0E1ZF9HV1VpOER4VzNsZE9ZV0dpeHNHNGJwNkVuOGtWM1dtVjhCaWx5R3JvTU1nIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbEJ2YVc1MFQyWlFjbVZ6Wlc1alpTSXNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKbmVEcFFiMmx1ZEU5bVVISmxjMlZ1WTJVaVhTd2lhWE56ZFdWeUlqb2laR2xrT25kbFlqcG5ZV2xoTFhndVpYVWlMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEEzTFRJeFZERXdPakl3T2pNeExqTTNOQ3N3TWpvd01DSXNJbU55WldSbGJuUnBZV3hUZFdKcVpXTjBJanA3SWtCcFpDSTZJbVY0T2xCdmFXNTBUMlpRY21WelpXNWpaU05qY3lJc0ltZDRPbTkzYm1Wa1Fua2lPbnNpUUdsa0lqb2laWGc2VEdWbllXeFFaWEp6YjI1Zk56RXlJMk56SW4wc0ltZDRPbWx1ZEdWeVkyOXVibVZqZEdWa1VHRnlkR2xqYVhCaGJuUnpJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHAzWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemN5STZleUpBYVdRaU9pSmxlRHBYWVhSbGNsVnpZV2RsUldabVpXTjBhWFpsYm1WemMxOHpOak1qWTNNaWZTd2laM2c2YVc1MFpYSmpiMjV1WldOMGFXOXVVRzlwYm5SSlpHVnVkR2xtYVdWeUlqcDdJa0JwWkNJNkltVjRPa2x1ZEdWeVkyOXVibVZqZEdsdmJsQnZhVzUwU1dSbGJuUnBabWxsY2w4Mk1UWWpZM01pZlN3aVozZzZiV0ZwYm5SaGFXNWxaRUo1SWpwN0lrQnBaQ0k2SW1WNE9rbHVkR1Z5Ym1WMFUyVnlkbWxqWlZCeWIzWnBaR1Z5WHpJeEkyTnpJbjBzSW1kNE9tVnVaWEpuZVZWellXZGxSV1ptYVdOcFpXNWplU0k2ZXlKQWFXUWlPaUpsZURwRmJtVnlaM2xWYzJGblpVVm1abWxqYVdWdVkzbGZORGd5STJOekluMHNJbWQ0T20xaGJuVm1ZV04wZFhKbFpFSjVJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHBzYjJOaGRHbHZiaUk2ZXlKQWFXUWlPaUpsZURwQlpHUnlaWE56WHprNU1pTmpjeUo5ZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLkpzZ2lsaDNrdnZHeGdjb2wxUzRBaVREc2kybFdUakR3RFJhOXdZLUI1clo1OWJpNUVoRkw5bTZ0SUV5QW5BNmttMk1zTDBmaV81cWNObzZDY01nS0hnIiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbE5sY25acFkyVlBabVpsY21sdVoxUmxjM1FpTENKMGVYQmxJanBiSWxabGNtbG1hV0ZpYkdWRGNtVmtaVzUwYVdGc0lpd2laM2c2VTJWeWRtbGpaVTltWm1WeWFXNW5JbDBzSW1semMzVmxjaUk2SW1ScFpEcDNaV0k2WjJGcFlTMTRMbVYxSWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF4TURveU1Eb3pNUzR6TnpRck1ESTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SkFhV1FpT2lKbGVEcFRaWEoyYVdObFQyWm1aWEpwYm1kVVpYTjBJMk56SWl3aVozZzZjbVZ4ZFdseVpXUk5aV0Z6ZFhKbGN5STZleUpBYVdRaU9pSmxlRHBOWldGemRYSmxYelUyTlNOamN5SjlMQ0puZURwd2NtOTJhV1JsY2tOdmJuUmhZM1JKYm1admNtMWhkR2x2YmlJNmV5SkFhV1FpT2lKbGVEcERiMjUwWVdOMFNXNW1iM0p0WVhScGIyNWZNakk1STJOekluMHNJbWQ0T210bGVYZHZjbVFpT2lKamNVcHNiM3BLYWlJc0ltZDRPbVJoZEdGUWIzSjBZV0pwYkdsMGVTSTZleUpBYVdRaU9pSmxlRHBFWVhSaFVHOXlkR0ZpYVd4cGRIbGZOemszSTJOekluMHNJbWQ0T21SaGRHRlFjbTkwWldOMGFXOXVVbVZuYVcxbElqb2lURWRRUkRJd01Ua2lMQ0puZURwa1lYUmhRV05qYjNWdWRFVjRjRzl5ZENJNmV5SkFhV1FpT2lKbGVEcEVZWFJoUVdOamIzVnVkRVY0Y0c5eWRGODFNRElqWTNNaWZTd2laM2c2WTNKNWNIUnZaM0poY0docFkxTmxZM1Z5YVhSNVUzUmhibVJoY21Seklqb2lVa1pET1RFME1pSXNJbWQ0T25CeWIzWnBjMmx2YmxSNWNHVWlPaUp3ZFdKc2FXTWlMQ0puZURwc1pXZGhiRVJ2WTNWdFpXNTBjeUk2VzNzaVFHbGtJam9pWlhnNlFXTmpaWE56UTI5dWRISnZiRTFoYm1GblpXMWxiblJmT0RrMUkyTnpJbjBzZXlKQWFXUWlPaUpsZURwQmMzTmxkSE5OWVc1aFoyVnRaVzUwWHpJeU1pTmpjeUo5TEhzaVFHbGtJam9pWlhnNlFuVnphVzVsYzNORGIyNTBhVzUxYVhSNVRXVmhjM1Z5WlhOZk5qUTJJMk56SW4wc2V5SkFhV1FpT2lKbGVEcERhR0Z1WjJWQmJtUkRiMjVtYVdkMWNtRjBhVzl1VFdGdVlXZGxiV1Z1ZEY4MU5qSWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9rTnZiWEJzYVdGdVkyVkJjM04xY21GdVkyVmZPVGMySTJOekluMHNleUpBYVdRaU9pSmxlRHBEYjNCNWNtbG5hSFJCYm1SSmJuUmxiR3hsWTNSMVlXeFFjbTl3WlhKMGVVUnZZM1Z0Wlc1MFh6VTFNeU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZRM1Z6ZEc5dFpYSkJkV1JwZEdsdVoxSnBaMmgwYzE4ME5USWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9rTjFjM1J2YldWeVJHRjBZVUZqWTJWemMxUmxjbTF6WHprd015TmpjeUo5TEhzaVFHbGtJam9pWlhnNlEzVnpkRzl0WlhKRVlYUmhVSEp2WTJWemMybHVaMVJsY20xelh6VXpNQ05qY3lKOUxIc2lRR2xrSWpvaVpYZzZSR0YwWVZCeWIzUmxZM1JwYjI1U1pXZDFiR0YwYVc5dVRXVmhjM1Z5WlhOZk1URXdJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEVaWFpsYkc5d2JXVnVkRU41WTJ4bFUyVmpkWEpwZEhsZk5qVXhJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEViMk4xYldWdWRFTm9ZVzVuWlZCeWIyTmxaSFZ5WlhOZk5ERTVJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEZiWEJzYjNsbFpWSmxjM0J2Ym5OcFltbHNhWFJwWlhOZk5EY2pZM01pZlN4N0lrQnBaQ0k2SW1WNE9rVnVkbWx5YjI1dFpXNTBZV3hKYlhCaFkzUlNaWEJ2Y25SZk56YzFJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEhiM1psY201dFpXNTBTVzUyWlhOMGFXZGhkR2x2YmsxaGJtRm5aVzFsYm5SZk5qRTVJMk56SW4wc2V5SkFhV1FpT2lKbGVEcEpibVp2Y20xaGRHbHZibE5sWTNWeWFYUjVUM0puWVc1cGVtRjBhVzl1WHpZMU55TmpjeUo5TEhzaVFHbGtJam9pWlhnNlNXNW1iM0p0WVhScGIyNVRaV04xY21sMGVWQnZiR2xqYVdWelh6azNPU05qY3lKOUxIc2lRR2xrSWpvaVpYZzZTVzVtYjNKdFlYUnBiMjVUWldOMWNtbDBlVkpwYzJ0TllXNWhaMlZ0Wlc1MFh6YzJNU05qY3lKOUxIc2lRR2xrSWpvaVpYZzZUR1ZuWVd4c2VVSnBibVJwYm1kQlkzUmZPRE01STJOekluMHNleUpBYVdRaU9pSmxlRHBQY0dWeVlYUnBiMjVoYkZObFkzVnlhWFI1WHpVNE5TTmpjeUo5TEhzaVFHbGtJam9pWlhnNlVHaDVjMmxqWVd4VFpXTjFjbWwwZVY4eE16TWpZM01pZlN4N0lrQnBaQ0k2SW1WNE9sQnliMk4xY21WdFpXNTBUV0Z1WVdkbGJXVnVkRk5sWTNWeWFYUjVYekl3TnlOamN5SjlMSHNpUUdsa0lqb2laWGc2VUhKdlpIVmpkRk5sWTNWeWFYUjVYemd4TlNOamN5SjlMSHNpUUdsa0lqb2laWGc2VW05c1pVRnVaRkpsYzNCdmJuTnBZbWxzYVhScFpYTmZNVE0xSTJOekluMHNleUpBYVdRaU9pSmxlRHBUWldOMWNtbDBlVWx1WTJsa1pXNTBUV0Z1WVdkbGJXVnVkRjh4TVRJalkzTWlmU3g3SWtCcFpDSTZJbVY0T2xObGNuWnBZMlZCWjNKbFpXMWxiblJQWm1abGNsODBOaklqWTNNaWZTeDdJa0JwWkNJNkltVjRPbFZ6WlhKRWIyTjFiV1Z1ZEdGMGFXOXVUV0ZwYm5SbGJtRnVZMlZmT0Rnd0kyTnpJbjFkTENKbmVEcHdiM056YVdKc1pWQmxjbk52Ym1Gc1JHRjBZVlJ5WVc1elptVnljeUk2ZXlKQWFXUWlPaUpsZURwRVlYUmhWSEpoYm5ObVpYSmZNelV4STJOekluMHNJbWQ0T21OMWMzUnZiV1Z5U1c1emRISjFZM1JwYjI1eklqcDdJa0JwWkNJNkltVjRPa04xYzNSdmJXVnlTVzV6ZEhKMVkzUnBiMjV6WHpNeE1DTmpjeUo5TENKbmVEcHdjbTkyYVdSbFpFSjVJanA3SWtCcFpDSTZJbVY0T2t4bFoyRnNVR1Z5YzI5dVh6Y3hNaU5qY3lKOUxDSm5lRHB6ZFdKRGIyNTBjbUZqZEc5eWN5STZleUpBYVdRaU9pSmxlRHBUZFdKRGIyNTBjbUZqZEc5eVh6YzNNeU5qY3lKOUxDSm5lRHB6WlhKMmFXTmxVRzlzYVdONUlqcDdJa0JwWkNJNkltVjRPbUZqWTJWemMxVnpZV2RsVUc5c2FXTjVJaXdpUUhSNWNHVWlPaUpuZURwQlkyTmxjM05WYzJGblpWQnZiR2xqZVNJc0ltZDRPbkJ2YkdsamVVeGhibWQxWVdkbElqb2lVbVZuYnlJc0ltZDRPbkJ2YkdsamVVUnZZM1Z0Wlc1MElqb2ljR0ZqYTJGblpTQmxlR0Z0Y0d4bFhHNWNibVJsWm1GMWJIUWdZV3hzYjNjZ1BTQm1ZV3h6WlZ4dVhHNWhiR3h2ZHlCN1hHNGdJQ0FnYVc1d2RYUXVkWE5sY2lBOVBTQmhiR2xqWlZ4dUlDQWdJR2x1Y0hWMExtRmpkR2x2YmlBOVBTQnlaV0ZrWEc1OUluMHNJbWQ0T25ObGNuWnBZMlZUWTI5d1pTSTZJbGRQU2xCV1MzcG9JaXdpWjNnNmFHOXpkR1ZrVDI0aU9uc2lRR2xrSWpvaVpYZzZWbWx5ZEhWaGJGSmxjMjkxY21ObFh6VXlJMk56SW4wc0ltZDRPbk5sY25acFkyVlBabVpsY21sdVoxUmxjbTF6UVc1a1EyOXVaR2wwYVc5dWN5STZleUpBYVdRaU9pSmxlRHBVWlhKdGMwRnVaRU52Ym1ScGRHbHZibk5mT0RVeUkyTnpJbjBzSW1kNE9tRm5aM0psWjJGMGFXOXVUMlpTWlhOdmRYSmpaWE1pT2x0N0lrQnBaQ0k2SW1WNE9sSmxjMjkxY21ObFh6TTBPQ05qY3lKOUxIc2lRR2xrSWpvaVpYZzZSR0YwWVVObGJuUmxjaU5qY3lKOUxIc2lRR2xrSWpvaVpYZzZVRzlwYm5SUFpsQnlaWE5sYm1ObEkyTnpJbjFkZlN3aWRtRnNhV1JWYm5ScGJDSTZJakl3TWpVdE1UQXRNamxVTVRBNk1qQTZNekV1TXpjMEt6QXhPakF3SW4wLlB5eXhzT2dvMkZ3ZzBMTUNvRXRDRDc0ZC1LZDU0S2RVbFdMS0ZMX2FqeENCQl9aZWpCdnl6M1JSdVdVejZuQ0hpOHVVbHJJcmV5aDV3bnBycFZpLU13IiwidHlwZSI6IkVudmVsb3BlZFZlcmlmaWFibGVDcmVkZW50aWFsIn0seyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImlkIjoiZGF0YTphcHBsaWNhdGlvbi92Yytqd3QsZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkluWmpLMnAzZENJc0ltTjBlU0k2SW5aaklpd2lhWE56SWpvaVpHbGtPbmRsWWpwbllXbGhMWGd1WlhVaUxDSnJhV1FpT2lKa2FXUTZkMlZpT21kaGFXRXRlQzVsZFNOclpYa3RNQ0o5LmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2Ym5NdlkzSmxaR1Z1ZEdsaGJITXZkaklpTENKb2RIUndjem92TDNjemFXUXViM0puTDJkaGFXRXRlQzlrWlhabGJHOXdiV1Z1ZENNaUxIc2laWGdpT2lKb2RIUndPaTh2WlhoaGJYQnNaUzV2Y21jaWZWMHNJa0JwWkNJNkltVjRPbU55WldSbGJuUnBZV3hKYzNOMVpYSWlMQ0owZVhCbElqcGJJbFpsY21sbWFXRmliR1ZEY21Wa1pXNTBhV0ZzSWl3aVozZzZTWE56ZFdWeUlsMHNJbWx6YzNWbGNpSTZJbVJwWkRwM1pXSTZaMkZwWVMxNExtVjFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOUzB3TnkweU1WUXhNRG95TURvek1TNHpOelFyTURJNk1EQWlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKQWFXUWlPaUpsZURwamNtVmtaVzUwYVdGc1NYTnpkV1Z5STJOeklpd2laM2c2WjJGcFlYaFVaWEp0YzBGdVpFTnZibVJwZEdsdmJuTWlPaUkwWW1RM05UVTBNRGszTkRRMFl6azJNREk1TW1JME56STJZekpsWm1FeE16Y3pORGcxWlRoaE5UVTJOV1E1TkdRME1URTVOVEl4TkdNMVpUQmpaV0l6SW4wc0luWmhiR2xrVlc1MGFXd2lPaUl5TURJMUxURXdMVEk1VkRFd09qSXdPak14TGpNM05Dc3dNVG93TUNKOS5PUldXZkk4Y2pybWF1blBDd1hnTmp1amRHU0lGcUd1dHFpLUxKQ1k2bWJlU1dqbmxScmNKNWEwX0txVUxueUZLRkc1RkdVTnltLWx4dkpwdkFtNFFOdyIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9LHsiQGNvbnRleHQiOiJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJpZCI6ImRhdGE6YXBwbGljYXRpb24vdmMrand0LGV5SmhiR2NpT2lKUVV6STFOaUlzSW1semN5STZJbVJwWkRwM1pXSTZjbVZuYVhOMGNtRjBhVzl1Ym5WdFltVnlMbTV2ZEdGeWVTNXNZV0l1WjJGcFlTMTRMbVYxT25ZeUlpd2lhMmxrSWpvaVpHbGtPbmRsWWpweVpXZHBjM1J5WVhScGIyNXVkVzFpWlhJdWJtOTBZWEo1TG14aFlpNW5ZV2xoTFhndVpYVTZkaklqV0RVd09TMUtWMHNpTENKcFlYUWlPakUzTlRNd09EVXlNRFk0Tnpnc0ltVjRjQ0k2TVRjMk1EZzJNVEl3TmpnM09Td2lZM1I1SWpvaWRtTXJiR1FpTENKMGVYQWlPaUoyWXl0c1pDdHFkM1FpZlEuZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MMmRoYVdFdGVDOWtaWFpsYkc5d2JXVnVkQ01pWFN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJbWQ0T2xaaGRFbEVJbDBzSW1sa0lqb2lhSFIwY0hNNkx5OWxlR0Z0Y0d4bExtOXlaeTlqY21Wa1pXNTBhV0ZzY3k4eE1qTWlMQ0p1WVcxbElqb2lWa0ZVSUVsRUlpd2laR1Z6WTNKcGNIUnBiMjRpT2lKV1lXeDFaU0JCWkdSbFpDQlVZWGdnU1dSbGJuUnBabWxsY2lJc0ltbHpjM1ZsY2lJNkltUnBaRHAzWldJNmNtVm5hWE4wY21GMGFXOXViblZ0WW1WeUxtNXZkR0Z5ZVM1c1lXSXVaMkZwWVMxNExtVjFPbll5SWl3aWRtRnNhV1JHY205dElqb2lNakF5TlMwd055MHlNVlF3T0Rvd05qbzBOaTQ0Tnpnck1EQTZNREFpTENKMllXeHBaRlZ1ZEdsc0lqb2lNakF5TlMweE1DMHhPVlF3T0Rvd05qbzBOaTQ0Tnprck1EQTZNREFpTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SnBaQ0k2SW1oMGRIQnpPaTh2WlhoaGJYQnNaUzV2Y21jdmMzVmlhbVZqZEhNdk1USXpJaXdpZEhsd1pTSTZJbWQ0T2xaaGRFbEVJaXdpWjNnNmRtRjBTVVFpT2lKQ1JUQTNOakkzTkRjM01qRWlMQ0puZURwamIzVnVkSEo1UTI5a1pTSTZJa0pGSW4wc0ltVjJhV1JsYm1ObElqcDdJbWQ0T21WMmFXUmxibU5sVDJZaU9pSm5lRHBXWVhSSlJDSXNJbWQ0T21WMmFXUmxibU5sVlZKTUlqb2lhSFIwY0RvdkwyVmpMbVYxY205d1lTNWxkUzkwWVhoaGRHbHZibDlqZFhOMGIyMXpMM1pwWlhNdmMyVnlkbWxqWlhNdlkyaGxZMnRXWVhSVFpYSjJhV05sSWl3aVozZzZaWGhsWTNWMGFXOXVSR0YwWlNJNklqSXdNalV0TURjdE1qRlVNRGc2TURZNk5EWXVPRGMzS3pBd09qQXdJbjE5LmlvR2pjMWhKRXNuZFNpZ1Q5UTYxM3ZEelc4Unk4YTlsOWlaTEppTExZU3VWMmNUc084SVE1eHpydHp3MXJncUd6N1lqODVaR1VPMVhlU2N2YnFlTElLU3F0cENhVVd6UXM1a3pLTkJlaHNsbnJmWG1NUi04Z3VNelhXc1VVc3BsOXR1WnFadk9RckVPa1I2T1J6YXlMU0VyUFdBakNJbXBQTElvOTBnczFIdzcwYlNjM2FDdVExaHFobzl3SGNWS0doVlMtbHg1QzhmQmM0eHNZdjR6MTdCVnFUSzRlcS1nanJxZVdEZmNDTno4cmVUeUZHWjBMM3o2d0hiV21YQ2tDaHByTHI5R1YwanJmRjlxUDIxM2RFM21BWE5FeTNOdkttZkxjWG90SWpwRzNkV295dFZHenVIWHM3c2RzYXRBcGFOUGlDcEZwWmJaREYzbWJuc3pqQSIsInR5cGUiOiJFbnZlbG9wZWRWZXJpZmlhYmxlQ3JlZGVudGlhbCJ9XSwiaXNzdWVyIjoiZGlkOndlYjpnYWlhLXguZXUiLCJ2YWxpZEZyb20iOiIyMDI1LTA3LTIxVDEwOjIyOjExLjAwMyswMjowMCIsInZhbGlkVW50aWwiOiIyMDI1LTEwLTI5VDEwOjIyOjExLjAwMyswMTowMCJ9.VcPSWoHC6PPUWyXqiUueBA1IPxKhMSqQHzHjjAvA5aAEWYQGvbSukbWWKtmN43Pye7JXLU_GFZE02s8LJQ-1xw";
        // } 

        const isValid = await verifyVpJwt(rawVp);
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
        console.log("[GAIA-X] ✅ Received Compliance VC (JWT):", complianceVcJwt.substring(0, 400) + "...");
        alert("✅ GAIA-X Compliance VC successfully created and received.");
    } catch (error) {
        console.error("[GAIA-X] Compliance VC creation failed:", error);
        alert(`❌ GAIA-X Compliance VC creation failed: ${error.message}`);
    }
}






// ===== GAIA-X VC Operations (Step 2a: Self-Issue T&C VC) =====
async function selfIssueTermsAndConditionsVc() {
    const notification = document.getElementById("step2Notification");
    const selfIssueBtn = document.getElementById("selfIssueBtn");
    
    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);

    selfIssueBtn.disabled = true;
    selfIssueBtn.textContent = "Issuing T&C VC...";
    notification.style.display = "none";

    try {
        const participantDid = document.getElementById("participantDidInput").value;
        if (!participantDid) throw new Error("Participant DID is required.");

        const termsUrl = `${APP_BASE_URL}/.well-known/gaia-x/tc/tc.txt`;
        const termsResponse = await fetch(termsUrl);
        if (!termsResponse.ok) throw new Error(`Failed to fetch Terms & Conditions from ${termsUrl}`);
        const termsText = await termsResponse.text();

        // Compute SHA-512 hash
        const encoder = new TextEncoder();
        const data = encoder.encode(termsText);
        const hashBuffer = await crypto.subtle.digest("SHA-512", data);
        const hashHex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");

        const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            type: ["VerifiableCredential", "gx:TermsAndConditions"],
            "@id": vcId,
            issuer: participantDid,
            "validFrom": validFrom,
            "validUntil": validUntil,
            credentialSubject: {
                "@id": participantDid,
                "gx:hash": hashHex,
                "gx:url": { "@value": termsUrl, "@type": "xsd:anyURI" }
            }
        };

        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] T&C VC Payload (Unsigned):\n${JSON.stringify(vcPayload, null, 2)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }
        // Add alert to show the vcPayload
        alert("Here is the debug T&C VC Payload:\n" + JSON.stringify(vcPayload, null, 2));



        // Sign VC
        const response = await fetch("/api/sign-vc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vcPayload })
        });
        const rawVc = await response.text();
        // Save globally
        gaiaxTermsVcJwt = rawVc;
        // Optional: also save in localStorage for persistence
        localStorage.setItem("gaiax_terms_vc_jwt", rawVc);

        if (!response.ok) throw new Error(`VC signing failed with status ${response.status}: ${rawVc}`);

        const decodedPayload = decodeJwt(rawVc);
        alert("✅ T&C VC successfully self-issued");
        // Display signed JWT and payload
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] T&C VC Signed (Raw JWT):\n${rawVc}\n[Decoded Payload]:\n${JSON.stringify(decodedPayload, null, 2)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

        termsAndConditionsVcPayload = { vcId, rawVc, decoded: decodedPayload };

        // Update display container
        const step2VcContainer = document.getElementById("step2VcContainer");
        step2VcContainer.style.display = "block";
        document.getElementById("step2DecodedVcDisplay").textContent =
            `--- Terms & Conditions VC ---\nRaw JWT:\n${rawVc}\n\nPayload:\n${JSON.stringify(decodedPayload, null, 2)}`;

        notification.textContent = "✅ Terms & Conditions VC successfully issued. Starting Legal Participant VC...";
        notification.className = "notification-success";
        notification.style.display = "block";

        // Proceed to Legal Participant VC
        await selfIssueLegalParticipantVc(vcId);

    } catch (error) {
        notification.textContent = `❌ Failed to issue Terms & Conditions VC: ${error.message}`;
        notification.className = "notification-error";
        notification.style.display = "block";
        console.error("T&C VC self-issue failed:", error);
    } finally {
        selfIssueBtn.disabled = false;
        selfIssueBtn.textContent = "Self-Issue Participant & T&C VC";
    }
}


// ===== GAIA-X VC Operations (Step 2b: Self-Issue Legal Participant VC) =====
async function selfIssueLegalParticipantVc(tcVcId) {
    const notification = document.getElementById("step2Notification");
    const selfIssueBtn = document.getElementById("selfIssueBtn");

    const now = new Date();
    const expiryDate = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 90); // +90 days
    const validFrom = toRfc3339WithLocalOffset(now);
    const validUntil = toRfc3339WithLocalOffset(expiryDate);
    selfIssueBtn.textContent = "Issuing Legal Participant VC...";

    try {
        const legalRegistrationId = document.getElementById("legalRegIdInput").value;
        const participantDid = document.getElementById("participantDidInput").value;
        const hqCountry = document.getElementById("hqCountryInput").value;
        const legalCountry = document.getElementById("legalCountryInput").value;
        if (!legalRegistrationId || !participantDid) throw new Error("Missing required registration data.");

        const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            type: ["VerifiableCredential", "gx:LegalPerson"],
            "@id": vcId,
            issuer: participantDid,
            validFrom: validFrom,
            validUntil: validUntil,
            credentialSubject: {
                "@id": participantDid,
                "gx:legalAddress": legalCountry,
                "gx:subOrganisationOf": participantDid,
                "gx:registrationNumber": legalRegistrationId,
                "gx:headquartersAddress": hqCountry
            }
           // evidence: {
           //     "gx:evidenceOf": "gx:TermsAndConditions",
           //     "gx:evidenceDocument": tcVcId
            }
    

        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] Legal Participant VC Payload (Unsigned):\n${JSON.stringify(vcPayload, null, 2)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

        // Sign VC
        const response = await fetch("/api/sign-vc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vcPayload })
        });
        const rawVc = await response.text();
        if (!response.ok) throw new Error(`Legal Participant VC signing failed with status ${response.status}: ${rawVc}`);

        const decodedPayload = decodeJwt(rawVc);

                // Save globally
        gaiaxParticipantVcJwt = rawVc;
        alert("✅ Participant VC successfully obtained");

        // Optional: also save in localStorage
        localStorage.setItem("gaiax_participant_vc_jwt", rawVc);

        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] Legal Participant VC Signed (Raw JWT):\n${rawVc}\n[Decoded Payload]:\n${JSON.stringify(decodedPayload, null, 2)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

        legalParticipantVcPayload = { vcId, rawVc, decoded: decodedPayload };

        // Update display container
        const step2VcDisplay = document.getElementById("step2DecodedVcDisplay");
        step2VcDisplay.textContent += `\n\n--- Legal Participant VC ---\nRaw JWT:\n${rawVc}\n\nPayload:\n${JSON.stringify(decodedPayload, null, 2)}`;

        notification.textContent = "🎉 Step 2 Complete! Both VCs successfully issued.";
        notification.className = "notification-success";

    } catch (error) {
        notification.textContent = `❌ Failed to issue Legal Participant VC: ${error.message}`;
        notification.className = "notification-error";
        console.error("Legal Participant VC self-issue failed:", error);
    }
        // FINALLY BLOCK ADDED HERE
    finally {
        // Reset the button text regardless of success or failure
        selfIssueBtn.textContent = "Self-Issue Participant & T&C VC";
    }
    enableGaiaxStep3(); // Enable Step 3 after attempting Legal Participant VC
}

function enableGaiaxStep3() {
    // Show the Step 3 card
    const step3Card = document.getElementById("step3Card");
    if (step3Card) {
        step3Card.style.display = 'block';
    }

    // Get and enable the Step 3 button
    const requestComplianceVcBtn = document.getElementById("requestComplianceVcBtn");
    
    if (requestComplianceVcBtn) {
        requestComplianceVcBtn.disabled = false;
        
        // CRUCIAL FIX: ATTACH THE LISTENER FOR STEP 3
        requestComplianceVcBtn.addEventListener("click", gaiaxComplianceVc);
        console.log("GAIA-X Step 3 button enabled and listener attached.");
    }
}



// ===== Tem Debug =====
function logGSI(msg) {
    console.log(msg);
    const el = document.getElementById('gsiDebug');
    if(el) el.textContent = msg;
}

// ===== Logout =====
window.logout = async function() {
  try {
    // 🧹 1. Local cleanup
    currentUser = null;
    if (currentSse) currentSse.close();
    currentSse = null;

    document.getElementById("topbarUserInfo").innerHTML = "";
    document.getElementById("loginPanel").style.display = "block";
    document.getElementById("todoPanel").style.display = "none";
    document.getElementById("didPanel").style.display = "none";

    document.getElementById("todoTab").disabled = true;
    document.getElementById("didTab").disabled = true;
    document.getElementById("gaiaxTab").disabled = true;

    // 🧾 2. Tell backend to clear secure cookie
    await fetch("/api/session/logout", { 
      method: "POST", 
      credentials: "include" // ✅ include cookie in request
    });

    // 🚫 3. If Google Sign-In used, disable auto-login
    if (window.google?.accounts?.id) {
      window.google.accounts.id.disableAutoSelect();
    }

    // 🧠 4. Clear any local storage caches (optional)
    localStorage.clear();
    sessionStorage.clear();

    console.log("✅ User logged out successfully.");
  } catch (err) {
    console.error("❌ Logout failed:", err);
  }
};




// ===== DOM Ready =====
window.addEventListener("DOMContentLoaded", async () => {

    // --- 1. INITIALIZE GLOBAL UI VARIABLES ---
    // Assign DOM elements to the global variables defined outside
    tabElements.loginTab = document.getElementById("loginTab");
    tabElements.todoTab = document.getElementById("todoTab");
    tabElements.didTab = document.getElementById("didTab");
    tabElements.gaiaxTab = document.getElementById("gaiaxTab");
    
    panels.login = document.getElementById("loginPanel");
    panels.todo = document.getElementById("todoPanel");
    panels.did = document.getElementById("didPanel");
    panels.gaiax = document.getElementById("gaiaxPanel");
    
    // --- 2. Check if there is an existing session ---
    // The checkExistingSession function now calls the global showLoginOptions on fail.
    const hasSession = await checkExistingSession();
    
    // If the check was successful, the handlePostLogin (called by checkExistingSession)
    // will have already called showMainApp() and showTasks().
    // If the check failed, showLoginOptions() was called, loading the 'login' tab.
    
    // --- 3. Attach Event Listeners (using global references) ---
    const rowBtn = document.getElementById("rowBtn");
    const myInput = document.getElementById("myInput");
    const walletLoginBtn = document.getElementById("walletLoginBtn");
    const logoutBtn = document.querySelector(".logout-btn");
    const selfIssueBtn = document.getElementById("selfIssueBtn");
    const requestVcBtn = document.getElementById("requestVcBtn");
    const complianceBtn = document.getElementById("requestComplianceVcBtn"); // <--- NEW BUTTON
    const closeModalBtn = document.getElementById("closeModal");

    rowBtn?.addEventListener("click", addTask);
    myInput?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") addTask();
    });

    walletLoginBtn?.addEventListener("click", initiateSsiLogin);
    // Ensure you define window.logout function if it's used globally
    logoutBtn?.addEventListener("click", window.logout); 
    selfIssueBtn?.addEventListener("click", selfIssueTermsAndConditionsVc); // To get the self-issued VCs
    requestVcBtn?.addEventListener("click", requestGaiaxVc); 
        // === NEW: GAIA-X Compliance VC button handler ===
    complianceBtn?.addEventListener("click", async () => {
        complianceBtn.disabled = true;
        complianceBtn.textContent = "Requesting Compliance VC...";
        try {
            await gaiaxComplianceVc();
        } catch (err) {
            console.error("❌ Compliance VC request failed:", err);
            alert("Failed to request Compliance VC. Check console for details.");
        } finally {
            complianceBtn.disabled = false;
            complianceBtn.textContent = "Request Compliance VC";
        }
    });
    closeModalBtn?.addEventListener("click", () => {
        document.getElementById("qrCodeModal").style.display = "none";
    });

    // ===== Tabs Listeners (Using global references and activateTab) =====
    // The previous definition of activateTab, panels, and tab references is removed here
    // as it is now global.

    tabElements.loginTab?.addEventListener("click", () => activateTab("login"));
    tabElements.todoTab?.addEventListener("click", () => { 
        if (!tabElements.todoTab.disabled) activateTab("todo"); 
    });
    tabElements.didTab?.addEventListener("click", async () => {
        if (!tabElements.didTab.disabled) {
            activateTab("did");
            try {
                const didDoc = await generateDidDoc();
                document.getElementById("didJson").textContent = JSON.stringify(didDoc, null, 2);
            } catch (err) {
                document.getElementById("didJson").textContent = "Error: " + err.message;
                console.error(err);
            }
        }
    });
    tabElements.gaiaxTab?.addEventListener("click", () => {
        if (!tabElements.gaiaxTab.disabled) {
            // Fetch GAIA-X shapes early and store them globally
            fetchAndParseGaiaxShapes().then(shapes => {
                gaiaxShapes = shapes;
            });
            // NEW: Pre-populate fields using data from Step 1 VC
            prepopulateGaiaxStep2Fields(); // <--- ADD THIS CALL
            // ... (rest of GAIA-X logic) ...
            activateTab("gaiax");
        }
    });
});



// ===== Service Worker =====
// ===== Service Worker with Auto-Update =====
if ('serviceWorker' in navigator) {
    window.addEventListener('load', async () => {
        try {
            const registration = await navigator.serviceWorker.register('/sw.js');
            console.log('Service Worker registered:', registration.scope);

            // Listen for updates to the service worker
            registration.onupdatefound = () => {
                const newWorker = registration.installing;
                console.log('New service worker found:', newWorker);

                newWorker.onstatechange = () => {
                    if (newWorker.state === 'installed') {
                        if (navigator.serviceWorker.controller) {
                            // New update available, force reload
                            console.log('New version available, reloading...');
                            window.location.reload();
                        } else {
                            console.log('Service worker installed for the first time.');
                        }
                    }
                };
            };
        } catch (err) {
            console.error('Service Worker registration failed:', err);
        }
    });
}

// ===== Close SSE on unload =====
window.addEventListener("beforeunload", () => {
    if (currentSse) currentSse.close();
});
