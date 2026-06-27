# DeepScan – Advanced File Analysis & YARA Forensic Intelligence Suite

## Overview

DeepScan is a cybersecurity and digital forensics application developed using **Python**, **Flask**, and **YARA** to analyze suspicious files and detect potential malware. The system performs signature-based detection, entropy analysis, cryptographic hashing, and forensic report generation through an easy-to-use web dashboard.

This project was developed as an academic cybersecurity project to demonstrate practical malware analysis and digital forensic techniques.

## Features

* Secure file upload and analysis
* YARA rule-based malware detection
* File type identification
* MD5 and SHA-256 hash generation
* Entropy analysis for packed or obfuscated files
* Threat risk scoring
* PDF forensic report generation
* Interactive analysis dashboard

## Technologies Used

* Python
* Flask
* YARA
* ReportLab
* Matplotlib
* HTML
* CSS
* JavaScript

## Project Structure

DeepScan
│
├── Docs/
├── rules/
├── samples/
├── scripts/
├── static/
├── templates/
├── app.py
├── requirements.txt
└── README.md

## Installation

Clone the repository:

## git clone https://github.com/ashwanycs0-maker/DeepScan-Advanced-File-Analysis-YARA-Forensic-Intelligence-Suite.git

Move into the project folder:

## cd DeepScan-Advanced-File-Analysis-YARA-Forensic-Intelligence-Suite

Install dependencies:

## pip install -r requirements.txt

Run the application:

## python app.py

Open your browser and visit:

## http://127.0.0.1:5000

## How It Works

1. Upload a suspicious file.
2. Detect the file type.
3. Generate MD5 and SHA-256 hashes.
4. Calculate entropy to identify packed or obfuscated files.
5. Scan the file using YARA rules.
6. Calculate a threat score.
7. Generate a detailed forensic PDF report.

## Applications

* Malware Analysis
* Digital Forensics
* Incident Response
* Threat Intelligence
* Cybersecurity Research
* Security Operations Centers (SOC)

## Requirements

* Python 3.10+
* Flask
* matplotlib
* reportlab
* yara-python

##  Author

**Ashwany C Suresh**

Karunya Institute of Technology and Sciences (Deemed University)

## License

This project is intended for educational and cybersecurity research purposes.
