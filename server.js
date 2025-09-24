// ===== Imports =====
import express from "express";
import path from "path";
import bodyParser from "body-parser";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

// ===== Express setup =====
const app = express();
const PORT = process.env.PORT || 3000;

// ===== Middleware =====
// Enable CORS for all origins (adjust in production)
app.use(cors({
    origin: "*",          // Replace "*" with your frontend domain in production
    credentials: true
}));

// Parse JSON bodies
app.use(bodyParser.json());

// Serve static frontend
app.use(express.static(path.join(process.cwd(), "public")));

// ===== Todo API =====
let tasks = [];
let idCounter = 1;

// Get all tasks
app.get("/api/todos", (req, res) => {
    res.json(tasks);
});

// Add a task
app.post("/api/todos", (req, res) => {
    const { text } = req.body;
    if (text) {
        tasks.push({ id: idCounter++, text, checked: false });
        res.sendStatus(201);
    } else {
        res.sendStatus(400);
    }
});

// Update a task (toggle checked)
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

// Delete a task
app.delete("/api/todos/:id", (req, res) => {
    const id = parseInt(req.params.id, 10);
    tasks = tasks.filter(t => t.id !== id);
    res.sendStatus(200);
});

// ===== Serve index.html for SPA =====
app.get("/", (req, res) => {
    res.sendFile(path.join(process.cwd(), "public", "index.html"));
});

// ===== Optional SSE (placeholder) =====
// If you need to implement server-sent events in the future:
// app.get("/sse-server/stream-events/:nonce", (req, res) => {
//     // SSE logic here
// });

// ===== Start server =====
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

