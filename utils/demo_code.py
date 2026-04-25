"""
Demo mode — pre-loaded vulnerable code samples for 1-click demo.
"""

DEMO_SQL_INJECTION = '''# demo_app.py — Vulnerable Flask Login Endpoint
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    return sqlite3.connect("users.db")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    db = get_db()
    cursor = db.cursor()

    # VULNERABLE: raw string interpolation — SQL Injection
    query = f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "success", "message": f"Welcome {username}!"})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

@app.route("/user/<user_id>")
def get_user(user_id):
    db = get_db()
    cursor = db.cursor()
    # VULNERABLE: unsanitized path parameter
    cursor.execute(f"SELECT username, email FROM users WHERE id = {user_id}")
    row = cursor.fetchone()
    if row:
        return jsonify({"username": row[0], "email": row[1]})
    return jsonify({"error": "Not found"}), 404

if __name__ == "__main__":
    app.run(debug=True)
'''

DEMO_XSS = '''// demo_comments.js — Vulnerable Comment System
const express = require("express");
const app = express();
app.use(express.json());

let comments = [];

// VULNERABLE: stores and renders raw HTML — Stored XSS
app.post("/comment", (req, res) => {
    const { author, text } = req.body;
    comments.push({ author, text, timestamp: Date.now() });
    res.json({ success: true });
});

app.get("/comments", (req, res) => {
    // VULNERABLE: directly injects user content into HTML
    const html = comments.map(c =>
        `<div class="comment">
            <b>${c.author}</b>: ${c.text}
        </div>`
    ).join("");
    res.send(`<html><body>${html}</body></html>`);
});

// VULNERABLE: path traversal in file endpoint
app.get("/file", (req, res) => {
    const filename = req.query.name;
    const fs = require("fs");
    const content = fs.readFileSync("./uploads/" + filename, "utf8");
    res.send(content);
});

app.listen(3000);
'''

DEMO_SAMPLES = {
    "SQL Injection (Python/Flask)": DEMO_SQL_INJECTION,
    "XSS + Path Traversal (Node.js)": DEMO_XSS,
}
