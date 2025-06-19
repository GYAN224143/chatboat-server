require("dotenv").config(); // Must be first line
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
require("dotenv").config({ path: require("path").resolve(__dirname, ".env") });

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection
mongoose
  .connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 30000,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
  });

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
    origin: ["https://chatbot-adwance.netlify.app", "http://localhost:5173"],
    credentials: true,
  })
);

app.use(express.json());

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET environment variable not set!");
  process.exit(1);
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
app.get("/", (req, res) => {
  res.send(
    "Welcome to the Chatbot API! Use /api/auth/register to register or /api/auth/login to log in."
  );
});
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    database:
      mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    environment: process.env.NODE_ENV || "development",
    server: "Render",
  });
});

// Auth Routes
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    if (await User.exists({ username })) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const user = new User({
      username,
      password: await bcrypt.hash(password, 10),
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(201).json({
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (error) {
    console.error("Registration error:", error);
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
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      userId: user._id,
      username: user.username,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Chat Routes
app.post("/api/chat", authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    const userId = req.user.userId;

    if (!message?.trim()) {
      return res.status(400).json({ error: "Message is required" });
    }

    // Save user message
    await ChatMessage.create({
      userId,
      message: message.trim(),
      isUserMessage: true,
    });

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
    await ChatMessage.create({
      userId,
      message: botResponse,
      isUserMessage: false,
    });

    res.json({ response: botResponse });
  } catch (error) {
    console.error("Chat error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/chat/history", authenticateToken, async (req, res) => {
  try {
    const messages = await ChatMessage.find({
      userId: req.user.userId,
    }).sort({ createdAt: 1 });

    res.json(messages);
  } catch (error) {
    console.error("History error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Server Startup
const server = app
  .listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Try these endpoints:
  GET /health
  POST /api/auth/register
  POST /api/auth/login`);
  })
  .on("error", (err) => {
    console.error("Server failed to start:", err);
  });
