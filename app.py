from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
import os
from scripts.core import analyze
from scripts.report_pdf import generate_pdf

app = Flask(__name__)
app.secret_key = "secure_net_intelligence_key"

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Simple Hardcoded Auth for demo
        if username == "admin" and password == "kali":
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid Credentials")
            
    return render_template("login.html")

@app.route("/")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/scan", methods=["POST"])
def scan():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    file = request.files["file"]
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)

    data = analyze(path)
    return jsonify(data)

@app.route("/download_pdf", methods=["POST"])
def download_pdf():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    data = request.json["data"]
    generate_pdf(data)
    return send_file("output/report.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5000)