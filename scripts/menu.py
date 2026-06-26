import subprocess

print("1. Scan File")
print("2. Scan All Files")

choice = input("Enter choice: ")

if choice == "1":
    file = input("Enter file path: ")
    subprocess.run(["yara", "../rules/rules.yar", file])

elif choice == "2":
    subprocess.run(["yara", "-r", "../rules", "../samples"])

else:
    print("Invalid choice")
