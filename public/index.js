// ===== Imports =====
import { generateDidDoc } from "./didDoc.js";

// === NEW GLOBAL CONSTANT ===
const APP_BASE_URL = "https://family-organizer.onrender.com"; 
// When testing locally, change this to: "http://localhost:3000"
// This is used for all self-issued VC IDs and internal URL references.

// ===== Global State =====
let currentUser = null;
let currentNonce = null;
let currentSse = null;
let legalRegistrationVcPayload = null; 
let legalParticipantVcPayload = null; 
let gaiaxShapes = null; // To store the fetched SHACL shapes
let termsAndConditionsVcPayload = null; // To store T&C VC payload
// === VC Proof Constants ===



// ===== Utilities =====
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

// ===== Topbar & profile =====
function showUserProfile({ name, email, picture }) {
    const avatar = picture || "/images/pawn.png";
    const topbar = document.getElementById("topbarUserInfo");
    if (topbar) {
        topbar.innerHTML = `<img src="${avatar}" alt="avatar"><span>${email}</span>`;
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

    await fetch("/api/todos", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
    });

    inputBox.value = "";
    showTasks();
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
window.onSignIn = (response) => {
    console.log("=== Google Sign-In callback fired! ===");
    console.log("Full response:", response);

    if (!response || !response.credential) {
        console.warn("⚠️ No credential received. Likely an origin/client_id mismatch or blocked request.");
        return;
    }

    try {
        const credential = response.credential;
        console.log("Credential JWT received. Length:", credential.length);

        const payload = decodeJwt(credential);
        console.log("Decoded JWT payload:", payload);

        const email = payload.email;
        const name = payload.name || payload.given_name || "";
        const picture = payload.picture || "";

        const currentUser = { name, email, picture };
        console.log("Current user object:", currentUser);

        showUserProfile(currentUser);

        document.getElementById("loginPanel").style.display = "none";
        document.getElementById("todoPanel").style.display = "block";

        const todoTab = document.getElementById("todoTab");
        const didTab = document.getElementById("didTab");
        const loginTab = document.getElementById("loginTab");
        const gaiaxTab = document.getElementById("gaiaxTab");

        todoTab.disabled = false;
        didTab.disabled = false;
        gaiaxTab.disabled = false;

        loginTab.classList.remove("active");
        todoTab.classList.add("active");
        didTab.classList.remove("active");
        gaiaxTab.classList.remove("active");

        showTasks();
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
    if (currentSse) { currentSse.close(); currentSse = null; }

    const inner = JSON.parse(message.message || "{}");
    const code = inner.code;

    const tokenUrl = new URL("https://uself-issuer-agent.cyclops314.gleeze.com/auth/token");
    tokenUrl.searchParams.set("grant_type", "authorization_code");
    tokenUrl.searchParams.set("client_id", "https://uself-issuer-agent.cyclops314.gleeze.com");
    tokenUrl.searchParams.set("code", code);

    const tokenResp = await fetch(tokenUrl.toString(), {
        method: "POST",
        headers: { Accept: "application/json" },
        body: ""
    });

    const tokens = await tokenResp.json();
    const access = tokens.access_token;
    const decoded = decodeJwt(access);

    const email = decoded.claims?.userInfo?.email;
    const first = decoded.claims?.userInfo?.firstName || "";
    const last = decoded.claims?.userInfo?.lastName || "";
    const name = `${first} ${last}`.trim() || decoded.claims?.userInfo?.username || email;

    currentUser = { email, name, picture: null };
    showUserProfile(currentUser);

    document.getElementById("loginPanel").style.display = "none";
    document.getElementById("todoPanel").style.display = "block";

    const todoTab = document.getElementById("todoTab");
    const didTab = document.getElementById("didTab");
    const loginTab = document.getElementById("loginTab");
    const gaiaxTab = document.getElementById("gaiaxTab");

    gaiaxTab.disabled = false;
    todoTab.disabled = false;
    didTab.disabled = false;

    loginTab.classList.remove("active");
    todoTab.classList.add("active");
    didTab.classList.remove("active");
    gaiaxTab.classList.remove("active");
    

    showTasks();
    document.getElementById("qrCodeModal").style.display = "none";
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
        console.error("Critical Error: The HTML element for Step 2 (#step2Content) could not be found.");
        return; 
    }
    
    // 1. Legal Registration ID (Derived from Step 1 VC)
    const registrationId = vcSubject.legalRegistrationId || "";
    document.getElementById("legalRegIdInput").value = registrationId;

    // 2. Participant DID (Derived from Step 1 VC)
    const subjectDid = vcSubject.id || "";
    document.getElementById("participantDidInput").value = subjectDid;
    
    // 3. Derived Country Code (Extracted from Step 1 VC payload)
    // The country code is typically found in the credentialSubject as 'gx:countryCode'
    const derivedCountryCode = vcSubject.rawSubject?.["gx:countryCode"] || ""; 

    
    // 4. Terms and Conditions Hash (TRULY Self-Asserted: Removed mock value)
    document.getElementById("termsAndConditionsInput").value = ""; 
    document.getElementById("termsAndConditionsInput").placeholder = "e.g., SHA-512 hash of GAIA-X T&C";
    
    // 5. Headquarters Country Code (Using derived country code as default)
    document.getElementById("hqCountryInput").value = derivedCountryCode;
    
    // 6. Legal Address Country Code (Using derived country code as default)
    document.getElementById("legalCountryInput").value = derivedCountryCode;
    
    // Make the entire Step 2 container visible
    step2Content.style.display = "block"; 

    // Enable the Step 2 button
    if (selfIssueBtn) {
        selfIssueBtn.disabled = false;
    }
    
    // Scroll the new step into view
    step2Content.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ===== GAIA-X VC Operations (Utility: Fetch SHACL Shapes) =====

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

// ===== GAIA-X VC Operations (Step 2a: Self-Issue Terms and Conditions VC) =====
// ===== GAIA-X VC Operations (Step 2a: Self-Issue Terms and Conditions VC) =====
async function selfIssueTermsAndConditionsVc() {
    const notification = document.getElementById("step2Notification");
    const selfIssueBtn = document.getElementById("selfIssueBtn");
    
    selfIssueBtn.disabled = true;
    selfIssueBtn.textContent = "Issuing T&C VC...";
    notification.style.display = "none";

    try {
        const participantDid = document.getElementById("participantDidInput").value;
        if (!participantDid) {
            throw new Error("Participant DID is required.");
        }

        // GAIA-X T&C URL placeholder
        const termsUrl = `${APP_BASE_URL}/gaia-x/tc`; // could also get from input if dynamic

        // 1️⃣ Fetch the T&C file
        const termsResponse = await fetch(termsUrl);
        if (!termsResponse.ok) {
            throw new Error(`Failed to fetch Terms & Conditions from ${termsUrl}`);
        }
        const termsText = await termsResponse.text();

        // 2️⃣ Compute SHA-512 hash using Web Crypto API
        const encoder = new TextEncoder();
        const data = encoder.encode(termsText);
        const hashBuffer = await crypto.subtle.digest("SHA-512", data);
        // Convert hash to hex string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

        // 3️⃣ Construct VC Payload
        const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            type: ["VerifiableCredential", "gx:TermsAndConditions"],
            id: vcId,
            issuer: participantDid, // Self-issued
            credentialSubject: {
                id: participantDid,
                "gx:hash": hashHex,
                "gx:url": { 
                    "@value": termsUrl,
                    "@type": "xsd:anyURI"
                }
            }
        };

        // Debug log
        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] T&C VC Payload (Unsigned):\n${JSON.stringify(vcPayload, null, 2)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

        // 4️⃣ Call backend API to sign the VC
        const response = await fetch("/api/sign-vc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vcPayload })
        });

        const rawVc = await response.text();
        if (!response.ok) {
            throw new Error(`VC signing failed with status ${response.status}: ${rawVc}`);
        }

        const decodedPayload = decodeJwt(rawVc);

        termsAndConditionsVcPayload = {
            vcId,
            rawVc,
            decoded: decodedPayload
        };

        // Display T&C VC
        const step2VcContainer = document.getElementById("step2VcContainer");
        step2VcContainer.style.display = "block";
        document.getElementById("step2DecodedVcDisplay").textContent = 
            `--- Terms & Conditions VC Payload ---\n${JSON.stringify(decodedPayload, null, 2)}`;

        notification.textContent = "✅ Terms & Conditions VC successfully issued. Starting Legal Participant VC...";
        notification.className = "notification-success";
        notification.style.display = "block";

        // 5️⃣ Immediately proceed to issue the Legal Participant VC
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
// This runs second, using the T&C VC ID as evidence
async function selfIssueLegalParticipantVc(tcVcId) { 
    const notification = document.getElementById("step2Notification");
    const selfIssueBtn = document.getElementById("selfIssueBtn");
    
    // Update button text for this step
    selfIssueBtn.textContent = "Issuing Legal Participant VC...";

    try {
        const legalRegistrationId = document.getElementById("legalRegIdInput").value;
        const participantDid = document.getElementById("participantDidInput").value;
        const hqCountry = document.getElementById("hqCountryInput").value;
        const legalCountry = document.getElementById("legalCountryInput").value;
        
        if (!legalRegistrationId || !participantDid) {
            throw new Error("Missing required registration data from Step 1.");
        }

        // 1. Construct the VC Payload for LegalParticipant VC
        // *** USED APP_BASE_URL HERE ***
        const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;

        const vcPayload = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/gaia-x/development#"
            ],
            type: ["VerifiableCredential", "gx:LegalParticipant"],
            id: vcId,
            issuer: participantDid, // Self-issued
            credentialSubject: {
                id: participantDid,
                "gx:legalRegistrationNumber": legalRegistrationId, // This is the VAT ID
                "gx:headquartersCountry": hqCountry,
                "gx:legalPersonCountry": legalCountry
            },
            evidence: { // Referencing the T&C VC
                "gx:evidenceOf": "gx:TermsAndConditions",
                "gx:evidenceDocument": tcVcId // Use the ID of the T&C VC just issued
            }
        };
        // Add code to log the constructed payload for debugging
        console.log("Constructed Legal Participant VC Payload:", vcPayload);  
        // Log the constructed payload to the debug panel as well
        const debugBox = document.getElementById("ssiDebug"); 
        if (debugBox) {
            const logMessage = `VC Payload:\n${JSON.stringify(vcPayload, null, 2).substring(0, 15000)}...`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

        

        // 2. Call the backend API to self-sign the VC
        const response = await fetch("/api/sign-vc", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ vcPayload })
        });
        
        const rawVc = await response.text();

        if (!response.ok) {
            throw new Error(`Legal Participant VC signing failed with status ${response.status}: ${rawVc}`);
        }

        const decodedPayload = decodeJwt(rawVc);

        // Store the result globally
        legalParticipantVcPayload = {
            vcId: vcId,
            rawVc: rawVc,
            decoded: decodedPayload
        };
        
        // **APPEND Legal Participant VC PAYLOAD**
        const step2VcDisplay = document.getElementById("step2DecodedVcDisplay");
        step2VcDisplay.textContent += 
            `\n\n--- Legal Participant VC Payload ---\n${JSON.stringify(decodedPayload, null, 2)}`;
        
        notification.textContent = "🎉 Step 2 Complete! Both VCs successfully issued.";
        notification.className = "notification-success";
        
    } catch (error) {
        notification.textContent = `❌ Failed to issue Legal Participant VC: ${error.message}`;
        notification.className = "notification-error";
        console.error("Legal Participant VC self-issue failed:", error);
    } 
    // The finally block of the calling function (Step 2a) handles the button reset
}

// ===== Tem Debug =====
function logGSI(msg) {
    console.log(msg);
    const el = document.getElementById('gsiDebug');
    if(el) el.textContent = msg;
}

// ===== Logout =====
window.logout = function() {
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
};

// ===== DOM Ready =====
window.addEventListener("DOMContentLoaded", () => {
    showTasks();



    document.getElementById("rowBtn")?.addEventListener("click", addTask);
    document.getElementById("myInput")?.addEventListener("keypress", (e) => { if (e.key === "Enter") addTask(); });

    document.getElementById("walletLoginBtn")?.addEventListener("click", initiateSsiLogin);
    document.querySelector(".logout-btn")?.addEventListener("click", window.logout);
    document.getElementById("selfIssueBtn")?.addEventListener("click", selfIssueTermsAndConditionsVc);

    const loginTab = document.getElementById("loginTab");
    const todoTab = document.getElementById("todoTab");
    const didTab = document.getElementById("didTab");
    const gaiaxTab = document.getElementById("gaiaxTab");
    const requestVcBtn = document.getElementById("requestVcBtn");

    loginTab?.addEventListener("click", () => {
        document.getElementById("loginPanel").style.display = "block";
        document.getElementById("todoPanel").style.display = "none";
        document.getElementById("didPanel").style.display = "none";
        document.getElementById("gaiaxPanel").style.display = "none";

        loginTab.classList.add("active");
        todoTab?.classList.remove("active");
        didTab?.classList.remove("active");
        gaiaxTab?.classList.remove("active");
    });

    todoTab?.addEventListener("click", () => {
        if (!todoTab.disabled) {
            document.getElementById("loginPanel").style.display = "none";
            document.getElementById("todoPanel").style.display = "block";
            document.getElementById("didPanel").style.display = "none";
            document.getElementById("gaiaxPanel").style.display = "none";
            
            loginTab.classList.remove("active");
            todoTab.classList.add("active");
            didTab?.classList.remove("active");
            gaiaxTab?.classList.remove("active");

        }
    });

    didTab?.addEventListener("click", async () => {
        if (!didTab.disabled) {
            document.getElementById("loginPanel").style.display = "none";
            document.getElementById("todoPanel").style.display = "none";
            document.getElementById("didPanel").style.display = "block";
            document.getElementById("gaiaxPanel").style.display = "none";

            loginTab.classList.remove("active");
            todoTab.classList.remove("active");
            didTab.classList.add("active");
            gaiaxTab?.classList.remove("active");

            try {
                const didDoc = await generateDidDoc();
                document.getElementById("didJson").textContent = JSON.stringify(didDoc, null, 2);
            } catch (err) {
                document.getElementById("didJson").textContent = "Error: " + err.message;
                console.error(err);
            }
        }
    });

    gaiaxTab?.addEventListener("click", () => {
        if (!gaiaxTab.disabled) {

            // Fetch GAIA-X shapes early and store them globally
            fetchAndParseGaiaxShapes().then(shapes => {
                gaiaxShapes = shapes;
            });

            document.getElementById("loginPanel").style.display = "none";
            document.getElementById("todoPanel").style.display = "none";
            document.getElementById("didPanel").style.display = "none";
            document.getElementById("gaiaxPanel").style.display = "block";
            loginTab.classList.remove("active");
            todoTab.classList.remove("active");
            didTab.classList.remove("active");
            gaiaxTab.classList.add("active");
        } 
    });

    // ===== GAIA-X Registration Number VC Request Listeners =====
    document.getElementById("requestVcBtn")?.addEventListener("click", requestGaiaxVc); 
    
    // ADDED MISSING LISTENER FOR STEP 2 BUTTON
    document.getElementById("selfIssueBtn")?.addEventListener("click", selfIssueTermsAndConditionsVc);


    // ===== QR Modal Close =====
    document.getElementById("closeModal")?.addEventListener("click", () => {
        document.getElementById("qrCodeModal").style.display = "none";
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