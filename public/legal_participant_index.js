// ===== Imports =====
import { generateDidDoc } from "./didDoc.js";

// === NEW GLOBAL CONSTANT ===
const APP_BASE_URL = "https://family-organizer.onrender.com"; 
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


// === VC Proof Constants ===

// app.use(express.static(path.join(__dirname, "public")));

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

// ===== GAIA-X VC Operations (Utility: Fetch SHACL Shapes) =====

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
    const vcId = `${APP_BASE_URL}/credentials/${uuidv4()}`;
    
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
        "issuer": "did:web:gaia-x.eu",
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
        const rawVp = await signResponse.text();
        console.log("[GAIA-X] Signed Compliance VP JWT:", rawVp);

        // 2️⃣ Send VP to GAIA-X Compliance endpoint (CORRECTED LOGIC)
        const complianceApiUrl = `${complianceUrlDirect}?vcId=${vcId}`;

        const complianceResponse = await fetch(complianceApiUrl, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json", 
                "Accept": "application/json" 
            },
            // The body must be the signed VP (`rawVp`), wrapped in JSON
            body: JSON.stringify({ rawVp })
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
        const data = await complianceResponse.json();
        // Assuming the response contains the new VC JWT, you can store it here, e.g., complianceVcJwt = data.vc;
        console.log("[GAIA-X] Received Compliance VC data:", data);

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
            @id: vcId,
            issuer: participantDid,
            "validFrom": validFrom,
            "validUntil": validUntil,
            credentialSubject: {
                @id: participantDid,
                "gx:hash": hashHex,
                "gx:url": { "@value": termsUrl, "@type": "xsd:anyURI" }
            }
        };

        const debugBox = document.getElementById("ssiDebug");
        if (debugBox) {
            debugBox.textContent += `\n[${new Date().toISOString()}] T&C VC Payload (Unsigned):\n${JSON.stringify(vcPayload, null, 2)}`;
            debugBox.scrollTop = debugBox.scrollHeight;
        }

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
            @id: vcId,
            issuer: participantDid,
            validFrom: validFrom,
            validUntil: validUntil,
            credentialSubject: {
                @id: participantDid,
                "gx:legalAddress": legalCountry,
                "gx:subOrganisationOf": participantDid,
                "gx:registrationNumber": legalRegistrationId,
                "gx:headquartersAddress": hqCountry
            }
           // evidence: {
           //     "gx:evidenceOf": "gx:TermsAndConditions",
           //     "gx:evidenceDocument": tcVcId
            }
        };

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
