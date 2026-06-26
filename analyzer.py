import os
import mimetypes
import math

def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)

    return round(entropy, 2)


def analyze_file(file):
    size = os.path.getsize(file)
    file_type = mimetypes.guess_type(file)[0]
    entropy = calculate_entropy(file)

    return {
        "size": size,
        "type": file_type,
        "entropy": entropy
    }