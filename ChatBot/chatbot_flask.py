from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import json, os, secrets
import openai

# ------------------------
# User File Setup
# ------------------------
USER_FILE = "users.json"

def load_users():
    if os.path.exists(USER_FILE):
        return json.load(open(USER_FILE))
    return {"demo": generate_password_hash("pass")}   # default user

def save_users(data):
    json.dump(data, open(USER_FILE, "w"))

users = load_users()

# ------------------------
# OpenAI Key
# ------------------------
try:
    openai.api_key = open("apikey.txt").read().strip()
except:
    openai.api_key = "DUMMY"

# ------------------------
# Flask App
# ------------------------
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ------------------------
# Login Page
# ------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    if "user" in session:
        return redirect(url_for("chat"))
    
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")

        if u in users and check_password_hash(users[u], p):
            session["user"] = u
            return redirect(url_for("chat"))
        return render_template("signin.html", error="Wrong username or password")

    return render_template("signin.html")

# ------------------------
# Signup
# ------------------------
@app.route("/signup", methods=["POST"])
def signup():
    u = request.form.get("new_username")
    p = request.form.get("new_password")

    if u in users:
        return render_template("signin.html", error="User already exists")

    users[u] = generate_password_hash(p)
    save_users(users)

    session["user"] = u
    return redirect(url_for("chat"))

# ------------------------
# Chat Page
# ------------------------
@app.route("/chat")
def chat():
    if "user" not in session:
        return redirect(url_for("home"))

    key = f"chat_{session['user']}"
    if key not in session:
        session[key] = [{"role": "system", "content": "You are Arman's Study Buddy."}]

    return render_template("bot.html", messages=session[key])

# ------------------------
# Send Message
# ------------------------
@app.route("/send", methods=["POST"])
def send():
    if "user" not in session:
        return redirect(url_for("home"))

    msg = request.form.get("message")
    key = f"chat_{session['user']}"

    session[key].append({"role": "user", "content": msg})
    session.modified = True

    try:
        res = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=session[key]
        )
        reply = res["choices"][0]["message"]["content"]
    except Exception as e:
        reply = f"API Error: {e}"

    session[key].append({"role": "assistant", "content": reply})
    session.modified = True

    return redirect(url_for("chat"))

# ------------------------
# Clear Chat
# ------------------------
@app.route("/clear", methods=["POST"])
def clear():
    if "user" not in session:
        return jsonify({"status": "error"}), 401

    session.pop(f"chat_{session['user']}", None)
    return jsonify({"status": "cleared"})

# ------------------------
# Logout
# ------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ------------------------
# Run App
# ------------------------
if __name__ == "__main__":
    app.run(debug=True)