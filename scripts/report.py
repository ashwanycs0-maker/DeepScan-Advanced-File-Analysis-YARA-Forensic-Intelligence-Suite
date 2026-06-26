import subprocess

file = input("Enter file path: ")

result = subprocess.run(
    ["yara", "../rules/rules.yar", file],
    capture_output=True,
    text=True
)

with open("../output/report.txt", "w") as f:
    f.write("Malware Scan Report\n\n")
    f.write(result.stdout)

print("Report generated!")
