import os, re, hashlib, mimetypes, math, subprocess

def calculate_entropy(file):
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


def real_file_type(file):
    with open(file, "rb") as f:
        header = f.read(4)
        if header.startswith(b"MZ"):
            return "Windows PE Executable"
        elif header.startswith(b"\x7fELF"):
            return "Linux ELF Binary"
        return "Unknown / Text"


def detect_features(file):
    features = []
    try:
        with open(file, "r", errors="ignore") as f:
            content = f.read().lower()

            if "http" in content:
                features.append("URL detected")
            if "password" in content:
                features.append("Sensitive keyword")
            if "malware" in content:
                features.append("Malware keyword")
            if "malicious" in content:
                features.append("Malicious behavior")
            if "attack" in content:
                features.append("Attack pattern")
            if "cmd" in content:
                features.append("Command execution")

    except:
        pass
    return features


def run_yara(file):
    result = subprocess.run(
        ["yara", "rules/rules.yar", file],
        capture_output=True,
        text=True
    )

    matches = result.stdout.strip().split("\n") if result.stdout else []

    return matches, result.stdout


def analyze(file):
    size = os.path.getsize(file)
    entropy = calculate_entropy(file)
    file_type = mimetypes.guess_type(file)[0]
    real_type = real_file_type(file)

    with open(file, "rb") as f:
        content_raw = f.read()
        content_text = content_raw.decode(errors="ignore").lower()

    md5 = hashlib.md5(content_raw).hexdigest()
    sha256 = hashlib.sha256(content_raw).hexdigest()

    matches, raw_yara = run_yara(file)
    features = detect_features(file)

    # 🔥 IMPROVED RISK LOGIC
    # High: Hard keywords like 'trojan' or extreme entropy
    if "trojan" in content_text or entropy > 7.5 or "Basic_Malware_Detection" in raw_yara:
        status = "HIGH"
    # Medium: High entropy or multiple suspicious features
    elif entropy > 6.0 or len(features) >= 2:
        status = "MEDIUM"
    # Low: Individual features like a URL
    elif len(features) > 0 or len(matches) > 0:
        status = "LOW"
    else:
        status = "SAFE"

    # Precise risk score calculation
    risk_score = min(100, (len(matches) * 25) + (len(features) * 15) + int(entropy * 5))
    if "trojan" in content_text: risk_score = max(risk_score, 90)

    return {
        "file": os.path.basename(file),
        "size": size,
        "type": file_type,
        "real_type": real_type,
        "entropy": entropy,
        "md5": md5,
        "sha256": sha256,
        "features": features,
        "matches": matches,
        "match_count": len(matches),
        "risk": risk_score,
        "status": status,
        "log": raw_yara if raw_yara else f"Content Analysis found: {', '.join(features)}"
    }