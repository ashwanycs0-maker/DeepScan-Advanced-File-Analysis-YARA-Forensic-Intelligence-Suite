import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess, os, mimetypes, re
import hashlib, datetime, math
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
# ================= LOGIN SYSTEM ================= #
def login():
    if user_entry.get() == "admin" and pass_entry.get() == "admin123":
        login_win.destroy()
        launch_main()
    else:
        messagebox.showerror("Error", "Invalid Username/Password")

login_win = tk.Tk()
login_win.title("Secure Login")
login_win.geometry("300x200")
login_win.configure(bg="#0d1117")

tk.Label(login_win, text="LOGIN", fg="cyan", bg="#0d1117",
         font=("Consolas", 16)).pack(pady=10)

user_entry = tk.Entry(login_win)
user_entry.insert(0, "admin")
user_entry.pack(pady=5)

pass_entry = tk.Entry(login_win, show="*")
pass_entry.insert(0, "admin123")
pass_entry.pack(pady=5)

tk.Button(login_win, text="Login", command=login,
          bg="#238636", fg="white").pack(pady=10)

# ================= CORE FEATURES ================= #

def save_report():
    content = output.get("1.0", tk.END)

    if not content.strip():
        messagebox.showerror("Error", "No report to save")
        return

    # Save text file
    file = filedialog.asksaveasfilename(defaultextension=".txt")

    if file:
        with open(file, "w") as f:
            f.write("Malware Scan Report\n\n")
            f.write(content)

        # Generate PDF automatically
        generate_pdf(content)
        
        
def generate_pdf(content):
    try:
        os.makedirs("output", exist_ok=True)

        doc = SimpleDocTemplate("output/report.pdf")
        styles = getSampleStyleSheet()

        elements = []
        elements.append(Paragraph("Malware Detection Report", styles["Title"]))
        elements.append(Paragraph(content.replace("\n", "<br/>"), styles["Normal"]))

        doc.build(elements)

        messagebox.showinfo("Success", "PDF saved in output/report.pdf")

    except Exception as e:
        messagebox.showerror("Error", str(e))
        
        
def calculate_entropy(file):
    try:
        with open(file, "rb") as f:
            data = f.read()
        if not data:
            return 0

        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 2)
    except:
        return 0


def real_file_type(file):
    try:
        with open(file, "rb") as f:
            header = f.read(4)
            if header.startswith(b"MZ"):
                return "Windows PE Executable"
            elif header.startswith(b"\x7fELF"):
                return "Linux ELF Binary"
            else:
                return "Unknown / Text"
    except:
        return "Unknown"


def pe_analysis(file):
    try:
        if file.lower().endswith(".exe"):
            size = os.path.getsize(file)
            return f"""
PE Analysis:
------------
Executable detected (.exe)
File Size: {size} bytes
⚠ Potentially dangerous file type
"""
        return ""
    except:
        return ""


def get_file_info(file):
    try:
        size = os.path.getsize(file)
        entropy = calculate_entropy(file)
        real_type = real_file_type(file)

        md5 = hashlib.md5(open(file, "rb").read()).hexdigest()
        sha256 = hashlib.sha256(open(file, "rb").read()).hexdigest()

        return f"""
File Analysis:
-----------------------
Path: {file}
Size: {size} bytes
Type: {mimetypes.guess_type(file)[0]}
Real Type: {real_type}
Entropy: {entropy}

MD5: {md5}
SHA256: {sha256}
"""
    except:
        return "File info error\n"


def detect_features(file):
    features = []
    try:
        with open(file, "r", errors="ignore") as f:
            content = f.read().lower()

            if re.search(r"http[s]?://", content):
                features.append("URL detected")
            if "password" in content:
                features.append("Sensitive keyword")
            if "malware" in content:
                features.append("Malware keyword")
            if "cmd" in content:
                features.append("Command execution")
            if "base64" in content:
                features.append("Encoded data")
    except:
        pass
    return features


def classify_risk(entropy, yara_output):
    yara_output = yara_output.lower()

    if entropy > 7.5 or "advanced" in yara_output:
        return "HIGH RISK ⚠", "red"
    elif entropy > 6:
        return "MEDIUM RISK ⚠", "orange"
    elif "url" in yara_output:
        return "LOW RISK ⚠", "yellow"
    else:
        return "SAFE ✅", "green"



def generate_chart(risk):
    import numpy as np

    for widget in chart_frame.winfo_children():
        widget.destroy()

    fig, ax = plt.subplots(figsize=(3.5, 2.5))

    fig.patch.set_facecolor("#1e293b")
    ax.set_facecolor("#1e293b")

    theta = np.linspace(np.pi, 2*np.pi, 100)

    ax.plot(np.cos(theta[:50]), np.sin(theta[:50]),
            color="#22c55e", linewidth=15)

    ax.plot(np.cos(theta[50:]), np.sin(theta[50:]),
            color="#ef4444", linewidth=15)

    # Needle
    if "HIGH" in risk:
        angle = 330
    elif "MEDIUM" in risk:
        angle = 270
    elif "LOW" in risk:
        angle = 230
    else:
        angle = 180

    angle = np.deg2rad(angle)

    ax.plot([0, 0.7*np.cos(angle)],
            [0, 0.7*np.sin(angle)],
            color="white", linewidth=2)

    ax.text(0, -0.2, risk.split()[0],
            color="white", ha="center",
            fontsize=12, fontweight="bold")

    ax.set_xlim(-1, 1)
    ax.set_ylim(-1, 0.5)

    ax.axis("off")

    canvas = FigureCanvasTkAgg(fig, chart_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(expand=True)

# ================= MAIN SCAN ================= #

def scan_file():
    file = entry.get()

    if not file or not os.path.exists(file):
        messagebox.showerror("Error", "Select valid file")
        return

    output.config(state="normal")
    output.delete("1.0", tk.END)

    # File Info
    # ===== FILE SUMMARY PANEL =====
    summary_box.config(state="normal")
    summary_box.delete("1.0", tk.END)
    summary_box.insert(tk.END, get_file_info(file))
    summary_box.config(state="disabled")

    # Features
    output.insert(tk.END, "\n=== Features ===\n", "blue")
    features = detect_features(file)
    for f in features:
        output.insert(tk.END, f"- {f}\n")

    # PE Analysis
    output.insert(tk.END, pe_analysis(file))

    # YARA
    try:
        result = subprocess.run(
            ["yara", "../rules/rules.yar", file],
            capture_output=True, text=True
        )
        yara_out = result.stdout

# ===== YARA PANEL =====
        yara_box.config(state="normal")
        yara_box.delete("1.0", tk.END)

        if yara_out.strip():
           yara_box.insert(tk.END, yara_out)
        else:
            yara_box.insert(tk.END, "No YARA matches found")

        yara_box.config(state="disabled")
    except: 
           yara_out = ""

    entropy = calculate_entropy(file)
    risk, color = classify_risk(entropy, yara_out)

    output.insert(tk.END, f"\n{risk}\n", color)

    generate_chart(risk)
    output.config(state="disabled")


# ================= UI ================= #

def launch_main():
    global entry, output, chart_frame, summary_box, yara_box

    root = tk.Tk()
    root.title("Malware Analytics PRO")
    root.geometry("1200x750")
    root.configure(bg="#0f172a")

    # ===== TITLE =====
    tk.Label(root, text="Malware Detection Dashboard",
             fg="#3b82f6", bg="#0f172a",
             font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=20, pady=10)

    # ===== PATH BAR =====
    entry = tk.Entry(root, bg="#1e293b", fg="white",
                     insertbackground="white",
                     font=("Consolas", 11), relief="flat")
    entry.pack(fill="x", padx=20, pady=5, ipady=6)

    # ===== BUTTONS =====
    btn_frame = tk.Frame(root, bg="#0f172a")
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="Browse",
              command=lambda: entry.insert(0, filedialog.askopenfilename()),
              bg="#3b82f6", fg="white", width=15).grid(row=0, column=0, padx=10)

    tk.Button(btn_frame, text="Scan File",
              command=scan_file,
              bg="#ef4444", fg="white", width=15).grid(row=0, column=1, padx=10)

    tk.Button(btn_frame, text="Save Report",
              command=save_report,
              bg="#22c55e", fg="white", width=15).grid(row=0, column=2, padx=10)

    # ===== MAIN GRID =====
    main = tk.Frame(root, bg="#0f172a")
    main.pack(fill="both", expand=True, padx=20, pady=10)

    # ---------- LEFT PANEL ----------
    left = tk.Frame(main, bg="#1e293b", width=350)
    left.grid(row=0, column=0, sticky="nsew", padx=10)

    tk.Label(left, text="File Summary & Metadata",
             bg="#1e293b", fg="white",
             font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=10)

    summary_box = tk.Text(left, height=15, bg="#0f172a", fg="white",
                      font=("Consolas", 10), relief="flat")
    summary_box.pack(fill="both", expand=True, padx=10, pady=10)

    # ---------- CENTER PANEL ----------
    center = tk.Frame(main, bg="#1e293b", width=350)
    center.grid(row=0, column=1, sticky="nsew", padx=10)

    tk.Label(center, text="Threat Metrics & Risk",
             bg="#1e293b", fg="white",
             font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=10)

    chart_frame = tk.Frame(center, bg="#1e293b")
    chart_frame.pack(fill="both", expand=True)

    # ---------- RIGHT PANEL ----------
    right = tk.Frame(main, bg="#1e293b", width=400)
    right.grid(row=0, column=2, sticky="nsew", padx=10)

    tk.Label(right, text="Detailed Analysis Feed",
             bg="#1e293b", fg="white",
             font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10, pady=10)

    frame = tk.Frame(right)
    frame.pack(fill="both", expand=True, padx=10, pady=10)

    scroll = tk.Scrollbar(frame)
    scroll.pack(side="right", fill="y")

    output = tk.Text(frame, bg="#020617", fg="#22c55e",
                     font=("Consolas", 10),
                     yscrollcommand=scroll.set)
    output.pack(fill="both", expand=True)

    scroll.config(command=output.yview)

    # ===== YARA SECTION =====
    yara_frame = tk.Frame(root, bg="#1e293b")
    yara_frame.pack(fill="x", padx=20, pady=10)

    tk.Label(yara_frame, text="YARA RULE MATCHES",
             bg="#1e293b", fg="#ef4444",
             font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=10)

    yara_box = tk.Text(yara_frame, height=5, bg="#0f172a", fg="white",
                       font=("Consolas", 10), relief="flat")
    yara_box.pack(fill="both", padx=10, pady=10)

    # ===== STATUS =====
    status = tk.Frame(root, bg="#0f172a")
    status.pack(fill="x")

    tk.Label(status, text="● System Status: ONLINE",
             fg="#22c55e", bg="#0f172a").pack(side="left", padx=20)

    tk.Label(status, text="YARA Engine v4.x",
             fg="#64748b", bg="#0f172a").pack(side="right", padx=20)

    # ===== COLORS =====
    output.tag_config("red", foreground="#ef4444")
    output.tag_config("orange", foreground="#f59e0b")
    output.tag_config("yellow", foreground="#eab308")
    output.tag_config("green", foreground="#22c55e")
    output.tag_config("blue", foreground="#3b82f6")

    main.columnconfigure(0, weight=1)
    main.columnconfigure(1, weight=1)
    main.columnconfigure(2, weight=1)

    root.mainloop()


   


login_win.mainloop()