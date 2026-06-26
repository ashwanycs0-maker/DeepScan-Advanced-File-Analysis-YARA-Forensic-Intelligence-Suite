import matplotlib.pyplot as plt

def generate_chart(risk_counts):
    labels = list(risk_counts.keys())
    values = list(risk_counts.values())

    plt.figure()
    plt.bar(labels, values)
    plt.title("Malware Risk Analysis")
    plt.xlabel("Risk Level")
    plt.ylabel("Count")

    plt.savefig("../output/chart.png")
    plt.close()