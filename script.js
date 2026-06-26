let lastData = null;
let barChart, pieChart;

// Initialize Charts on Load
window.onload = () => {
    const barCtx = document.getElementById('barChart').getContext('2d');
    barChart = new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: ['File Size', 'Entropy', 'Heuristics', 'Signatures'],
            datasets: [{
                label: 'Threat Intensity',
                data: [0, 0, 0, 0],
                backgroundColor: ['#3498db', '#f1c40f', '#e67e22', '#e74c3c']
            }]
        },
        options: {
            responsive: true,
            scales: { y: { beginAtZero: true, max: 100 } },
            plugins: { legend: { display: false } }
        }
    });

    const pieCtx = document.getElementById('pieChart').getContext('2d');
    pieChart = new Chart(pieCtx, {
        type: 'pie',
        data: {
            labels: ['Safe', 'Suspicious', 'Critical'],
            datasets: [{
                data: [100, 0, 0],
                backgroundColor: ['#2ecc71', '#f1c40f', '#e74c3c']
            }]
        },
        options: { responsive: true }
    });
};

function updatePathDisplay() {
    const fileInput = document.getElementById('fileInput');
    const pathDisplay = document.getElementById('file_path_display');
    if (fileInput.files.length > 0) {
        pathDisplay.value = "/media/sf_yara_project/samples/" + fileInput.files[0].name;
    }
}

function addLog(text, color = "var(--text-secondary)") {
    const feed = document.getElementById("analysis_feed");
    const line = document.createElement("div");
    line.className = "feed-line";
    line.style.color = color;
    line.innerText = text;
    feed.appendChild(line);
    feed.scrollTop = feed.scrollHeight;
}

function scan() {
    const fileInput = document.getElementById("fileInput");
    if (fileInput.files.length === 0) {
        alert("Please select a file first!");
        return;
    }

    const file = fileInput.files[0];
    const formData = new FormData();
    formData.append("file", file);

    const scanBtn = document.querySelector(".btn-green:nth-of-type(2)");
    scanBtn.innerText = "Scanning...";
    scanBtn.disabled = true;

    addLog(`[+] Initiating analysis for: ${file.name}`, "var(--accent-blue)");

    fetch("/scan", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        lastData = data; // Store full data for PDF
        // Update Metadata
        document.getElementById("res_path").innerText = "/media/sf_yara_project/samples/" + data.file;
        document.getElementById("res_size").innerText = data.size + " bytes";
        document.getElementById("res_type").innerText = data.type || "Unknown";
        document.getElementById("res_real").innerText = data.real_type;
        document.getElementById("res_md5").innerText = data.md5;
        document.getElementById("res_sha").innerText = data.sha256.substring(0, 32) + "...";

        // Update Entropy Metadata Bar
        const entropyPercent = (data.entropy / 8) * 100;
        document.getElementById("entropy_bar").style.width = entropyPercent + "%";
        
        // Update New Entropy Gauge
        const entropyAngle = (data.entropy / 8) * 180;
        document.getElementById("entropy_gauge").style.transform = `rotate(${entropyAngle}deg)`;
        document.getElementById("entropy_value_2").innerText = data.entropy.toFixed(2);
        
        // Dynamic Color for Entropy Value
        const entropyColor = data.entropy > 7 ? "var(--accent-red)" : data.entropy > 5 ? "var(--accent-yellow)" : "var(--accent-blue)";
        document.getElementById("entropy_value_2").style.color = entropyColor;



        // Update Risk Gauge
        const angle = (data.risk / 100) * 180;
        document.getElementById("risk_gauge").style.transform = `rotate(${angle}deg)`;
        document.getElementById("risk_status").innerText = data.status;
        document.getElementById("risk_status").style.color = 
            data.status === "HIGH" ? "var(--accent-red)" : 
            data.status === "MEDIUM" ? "var(--accent-yellow)" : "var(--accent-green)";

        // Update YARA Rules Display
        const yaraText = data.matches.length > 0 ? data.matches.join(", ") : "None Detected";
        document.getElementById("yara_rules_detected").innerText = yaraText;
        document.getElementById("yara_rules_detected").style.color = data.matches.length > 0 ? "var(--accent-red)" : "var(--text-primary)";

        // Update Charts
        if (barChart && pieChart) {
            barChart.data.datasets[0].data = [
                Math.min(100, data.size / 1000), // Normalized size
                entropyPercent,
                data.features.length * 20,
                data.match_count * 25
            ];
            barChart.update();

            const pieData = data.status === "HIGH" ? [10, 20, 70] : data.status === "MEDIUM" ? [30, 50, 20] : [90, 10, 0];
            pieChart.data.datasets[0].data = pieData;
            pieChart.update();
        }


        // Feed Logs
        addLog(`[+] Filesize: ${data.size} bytes`);
        addLog(`[+] Entropy detected: ${data.entropy}`);
        if (data.matches.length > 0) {
            addLog(`[!] ALERT: ${data.match_count} Signatures Matched!`, "var(--accent-red)");
        }
        addLog(`[+] Security Status: ${data.status}`, data.status === "SAFE" ? "var(--accent-green)" : "var(--accent-red)");

        scanBtn.innerText = "Scan File";
        scanBtn.disabled = false;
    })
    .catch(err => {
        addLog(`[!] Error during scan: ${err.message}`, "var(--accent-red)");
        scanBtn.innerText = "Scan File";
        scanBtn.disabled = false;
    });
}

function savePDF() {
    if (!lastData) {
        alert("Please run a scan first!");
        return;
    }
    fetch("/download_pdf", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({data: lastData})
    })
    .then(res => res.blob())
    .then(blob => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `Malware_Analysis_${lastData.file}.pdf`;
        a.click();
    });
}