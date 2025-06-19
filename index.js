require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const WebSocket = require("ws");

const app = express();
const PORT = process.env.PORT || 5000;

mongoose.set("strictQuery", true); // <-- Add this line

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  _id: { type: String, default: () => uuidv4() },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const chatMessageSchema = new mongoose.Schema({
  _id: { type: String, default: () => uuidv4() },
  userId: { type: String, required: true, ref: "User" },
  message: { type: String, required: true },
  isUserMessage: { type: Boolean, required: true },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const ChatMessage = mongoose.model("ChatMessage", chatMessageSchema);

// Middleware
app.use(
  cors({
    origin: ["http://localhost:5173", "https://chatbot-adwance.netlify.app"],
    credentials: true,
  })
);
app.use(express.json());

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Helper function to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.status(201).json({ token, userId: user._id, username: user.username });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, userId: user._id, username: user.username });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/chat", authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    const userId = req.user.userId;

    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    // Save user message
    const userMessage = new ChatMessage({
      userId,
      message,
      isUserMessage: true,
    });
    await userMessage.save();

    // Simulate bot response
    const botResponses = [
      "I'm a demo chatbot. In a real implementation, I'd connect to an LLM API.",
      "Thanks for your message! This is a simulated response.",
      "Interesting point! Normally I'd analyze this with AI.",
      "I'm just a demo, but I'd be smarter with a real AI backend.",
      "This is a placeholder response. A real chatbot would be more helpful!",
    ];
    const botResponse =
      botResponses[Math.floor(Math.random() * botResponses.length)];

    // Save bot response
    const botMessage = new ChatMessage({
      userId,
      message: botResponse,
      isUserMessage: false,
    });
    await botMessage.save();

    res.json({ response: botResponse });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/chat/history", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const messages = await ChatMessage.find({ userId }).sort({ createdAt: 1 });
    res.json(messages);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK" });
});

// Start the server
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});

// WebSocket server
const wss = new WebSocket.Server({ server });

wss.on("connection", (ws) => {
  console.log("New WebSocket connection");

  ws.on("message", (message) => {
    console.log(`Received: ${message}`);
    // Broadcast to all clients
    wss.clients.forEach((client) => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message.toString());
      }
    });
  });
});
