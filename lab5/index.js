const uuid = require("uuid");
const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const dotenv = require("dotenv");
const port = 3000;
const jwt = require("jsonwebtoken");
const axios = require("axios");
const fs = require("fs");

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", verifyToken, (req, res) => {
  res.json({
    username: req.user,
    logout: "http://localhost:3000/logout",
  });
});

app.get("/logout", (req, res) => {
  res.redirect("/");
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const response = await axios.post(
      `${process.env.API_URL}oauth/token`,
      {
        grant_type: "http://auth0.com/oauth/grant-type/password-realm",
        audience: process.env.AUDIENCE_URL,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        scope: "offline_access",
        realm: "Username-Password-Authentication",
        username: username,
        password: password,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
      }
    );
    res.status(201).json({
      access_token: response.data.access_token,
      username: username,
    });
  } catch (error) {
    console.log(error);
    res.status(401).json({ error: error.response?.data });
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

async function verifyToken(req, res, next) {
  const token = req.header("Authorization");
  if (!token) {
    return res.sendFile(path.join(__dirname + "/index.html"));
  }

  try {
    const privateKey = fs.readFileSync("private_key.pem", "utf8");
    jwt.verify(
      token,
      privateKey,
      { algorithms: ["RS256"] },
      async (err, decoded) => {
        if (err) {
          return res.sendFile(path.join(__dirname + "/index.html"));
        }
        const response = await axios.get(
          `${process.env.AUDIENCE_URL}users/${decoded.sub}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );
        req.user = response.data.name;
        next();
      }
    );
  } catch (error) {
    console.error("Private key file error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}
