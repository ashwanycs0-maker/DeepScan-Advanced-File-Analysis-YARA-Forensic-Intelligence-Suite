import subprocess

def run_yara(file):
    result = subprocess.run(
        ["yara", "../rules/basic_rules.yar", file],
        capture_output=True,
        text=True
    )

    matches = result.stdout.strip().split("\n") if result.stdout else []

    return {
        "raw": result.stdout,
        "matches": matches,
        "count": len(matches)
    }