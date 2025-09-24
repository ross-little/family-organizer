// ===== Global State =====
let currentUser = null;
let currentNonce = null;
let currentSse = null;

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
window.onSignIn = function(response) {
    try {
        const credential = response.credential;
        const payload = decodeJwt(credential);

        const email = payload.email;
        const name = payload.name || payload.given_name || "";
        const picture = payload.picture || "";

        currentUser = { name, email, picture };
        showUserProfile(currentUser);

        document.getElementById("loginPanel").style.display = "none";
        document.getElementById("todoPanel").style.display = "block";
        document.getElementById("todoTab").disabled = false;

        document.getElementById("loginTab").classList.remove("active");
        document.getElementById("todoTab").classList.add("active");

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

        // Render QR code safely
        if (qrCodeContainer) {
            new QRCode(qrCodeContainer, {
                text: decodeURIComponent(requestUri),
                width: 200,
                height: 200,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
        }

        // Mobile deep link
        const deepLink = document.createElement("a");
        deepLink.href = requestUri;
        deepLink.textContent = "👉 Open in Wallet App (mobile)";
        deepLink.className = "qr-mobile-link";
        deepLink.target = "_blank";
        deepLink.addEventListener("click", () => {
            qrModal.style.display = "none";
        });
        qrCodeContainer?.appendChild(deepLink);

        qrSpinner.style.display = "none";

        startListeningForLogin(currentNonce);

        // Reconnect SSE on focus/visibility
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
    if (currentSse) return; // already listening
    const subscribeUrl = `https://uself-issuer-agent.cyclops314.gleeze.com/sse-server/stream-events/${nonce}`;
    const es = new EventSource(subscribeUrl);
    currentSse = es;

    es.onmessage = async (event) => {
        try {
            const message = JSON.parse(event.data);
            if (message.status === "AUTHENTICATED") {
                handleAuthenticated(message);
            }
        } catch (err) {
            console.error("SSE message parse error:", err);
        }
    };

    es.onerror = (err) => {
        console.error("SSE error:", err);
        es.close();
        currentSse = null;
    };
}

// ===== Handle Authenticated =====
async function handleAuthenticated(message) {
    if (currentSse) {
        currentSse.close();
        currentSse = null;
    }

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
    document.getElementById("todoTab").disabled = false;

    showTasks();
    document.getElementById("qrCodeModal").style.display = "none";
}

// ===== Logout =====
function logout() {
    currentUser = null;
    if (currentSse) currentSse.close();
    currentSse = null;

    document.getElementById("topbarUserInfo").innerHTML = "";
    document.getElementById("loginPanel").style.display = "block";
    document.getElementById("todoPanel").style.display = "none";
    document.getElementById("todoTab").disabled = true;
}

// ===== DOM Ready =====
window.addEventListener("DOMContentLoaded", () => {
    showTasks();

    document.getElementById("rowBtn")?.addEventListener("click", addTask);
    document.getElementById("myInput")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") addTask();
    });

    document.getElementById("walletLoginBtn")?.addEventListener("click", initiateSsiLogin);
    document.querySelector(".logout-btn")?.addEventListener("click", logout);

    const loginTab = document.getElementById("loginTab");
    const todoTab = document.getElementById("todoTab");

    loginTab?.addEventListener("click", () => {
        document.getElementById("loginPanel").style.display = "block";
        document.getElementById("todoPanel").style.display = "none";
        loginTab.classList.add("active");
        todoTab?.classList.remove("active");
    });

    todoTab?.addEventListener("click", () => {
        if (!todoTab.disabled) {
            document.getElementById("loginPanel").style.display = "none";
            document.getElementById("todoPanel").style.display = "block";
            loginTab.classList.remove("active");
            todoTab.classList.add("active");
        }
    });

    document.getElementById("closeModal")?.addEventListener("click", () => {
        document.getElementById("qrCodeModal").style.display = "none";
    });
});

// ===== Service Worker =====
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js")
      .then(reg => console.log("Service Worker registered:", reg.scope))
      .catch(err => console.error("Service Worker registration failed:", err));
  });
}

// ===== Close SSE on unload =====
window.addEventListener("beforeunload", () => {
    if (currentSse) currentSse.close();
});

