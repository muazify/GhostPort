# 👻 GhostPort: The Blazing-Fast TCP Port Scanner 🚀

**GhostPort** is a powerful and efficient command-line tool for network reconnaissance. Designed for speed and accuracy, it leverages multi-threading to rapidly identify open TCP ports and grab service banners, often surpassing the performance of traditional scanners like Nmap in targeted scenarios.

---

## ✨ Key Features

* **⚡️ Ultra-Fast Scanning:** Utilizes multi-threading to scan a wide range of ports concurrently, significantly reducing scan time.
* **📡 Intelligent Banner Grabbing:** Retrieves service banners from open ports to provide detailed information about running services and their versions.
* **🎯 Precise Port Detection:** Accurately identifies both common and less common open ports.
* **🧠 Adaptive Timeout Handling:** Employs smarter timeout mechanisms to minimize false negatives and ensure reliable results.
* **💻 Command-Line Interface (CLI):** Offers a lean and powerful interface without the overhead of a graphical user interface.
* **🛠️ Built-in Dependencies:** Relies solely on Python's standard library (socket, threading, time), eliminating the need for external installations.

---

## 🛠️ Installation

### ⚙️ Prerequisites

* Python 3.6 or higher

### 📦 Getting Started

1.  Clone the GhostPort repository from GitHub:
    ```bash
    git clone [https://github.com/yourusername/GhostPort.git](https://github.com/yourusername/GhostPort.git)
    cd GhostPort
    ```

2.  Navigate to the GhostPort directory:
    ```bash
    cd GhostPort
    ```

---

## 🚀 Usage

Execute the `ghostport.py` script from your terminal:

```bash
sudo python3 ghostport.py [-h] -p PORTS [-t THREADS] [-w TIMEOUT] [-v] [-b] target
