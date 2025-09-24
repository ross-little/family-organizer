import express from "express";
import path from "path";
import bodyParser from "body-parser";

const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
app.use(bodyParser.json());
app.use(express.static(path.join(process.cwd(), "public")));

// ===== Todo API =====
let tasks = [];
let idCounter = 1;

app.get("/api/todos", (req, res) => {
    res.json(tasks);
});

app.post("/api/todos", (req, res) => {
    const { text } = req.body;
    if (text) {
        tasks.push({ id: idCounter++, text, checked: false });
    }
    res.sendStatus(201);
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

// ===== Serve frontend =====
app.get("/", (req, res) => {
    res.sendFile(path.join(process.cwd(), "public", "index.html"));
});

// ===== SSE Endpoint (optional for internal events) =====
// Currently you do not need polling or SSE server-side, so leave this out
// Any SSE logic will be handled by the external issuer-agent

// ===== Start server =====
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});



