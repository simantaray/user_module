const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const dbFilePath = path.join(__dirname, "db.json"); // Path to the JSON file
const JWT_SECRET = "your_jwt_secret"; // Secret for signing JWTs (in production, keep this secure)

// Middleware
app.use(bodyParser.json());

// Helper function to read JSON file
const readDB = () => {
  const data = fs.readFileSync(dbFilePath, "utf-8");
  return JSON.parse(data);
};

// Helper function to write to the JSON file
const writeDB = (data) => {
  fs.writeFileSync(dbFilePath, JSON.stringify(data, null, 2));
};

// Create user API
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  const db = readDB();
  const userExists = db.users.find((user) => user.username === username);

  if (userExists) {
    return res.status(400).json({ message: "User already exists" });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Add new user to the database (JSON file)
    db.users.push({ username, password: hashedPassword });
    writeDB(db);

    const token = jwt.sign({ username: username }, JWT_SECRET, {
      expiresIn: "24h",
    });

    res
      .status(201)
      .json({ message: `Welcome ${username}, you are logged in`, token });
  } catch (error) {
    res.status(500).json({ message: "Error creating user" });
  }
});

// Login user API
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  console.log("tiggered");

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  const db = readDB();
  const user = db.users.find((user) => user.username === username);

  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  // Compare password
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ message: "Invalid password" });
  }

  // Generate JWT
  const token = jwt.sign({ username: user.username }, JWT_SECRET, {
    expiresIn: "24h",
  });

  res
    .status(200)
    .json({
      message: `Welcome ${username}, you are logged in`,
      username: user.username,
      token,
    });
});

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(400).json({ message: "Invalid token" });
  }
};

app.get("/api/checktoken", authenticateJWT, (req, res) => {
  res.status(200).json({ message: "Token is valid", user: req.user });
});

// Protected route example
app.get("/api/protected", authenticateJWT, (req, res) => {
  res.status(200).json({
    message: `Hello, ${req.user.username}. This is a protected route.`,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
