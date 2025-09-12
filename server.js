// Express server
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid"); // uuid@7 works with require()

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Serve static frontend
app.use(express.static("public"));

// ===== In-memory Todo Store (one shared list for all family members) =====
let todos = []; // [{ id, text, checked }]

// ===== API Routes =====

// Get all todos
app.get("/api/todos", (req, res) => {
  res.json(todos);
});

// Add a todo
app.post("/api/todos", (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "Task text required" });

  const todo = { id: uuidv4(), text, checked: false };
  todos.push(todo);
  res.json(todo);
});

// Toggle/Update a todo
app.put("/api/todos/:id", (req, res) => {
  const { id } = req.params;
  const { checked } = req.body;

  const todo = todos.find(t => t.id === id);
  if (!todo) return res.status(404).json({ error: "Todo not found" });

  todo.checked = !!checked;
  res.json(todo);
});

// Delete a todo
app.delete("/api/todos/:id", (req, res) => {
  const { id } = req.params;
  todos = todos.filter(t => t.id !== id);
  res.json({ success: true });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});


