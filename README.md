# WinPingSweeper

## Overview

**Windows Ping Sweeper** is a tool for scanning networks and identifying active hosts using ICMP (Ping) and ARP protocols. It can detect live devices in a given network range and save the results for reference.

## Features

- **ICMP & ARP Scan**: Detects active hosts using ICMP and ARP.
- **Automatic/Custom IP Range**: Automatically detects your local subnet or allows custom ranges.
- **Concurrent Scanning**: Faster results with multi-threaded scans.
- **Results Saving**: Scan results are saved in the `Active_Hosts` folder with timestamps.

## Requirements

- **Windows OS**
- **Python 3.x** 
- **Third-party libraries**: `tqdm`, `colorama`
- **arp-ping.exe**: Download from [here](https://github.com/benjamingr/arp-ping).

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/Roger-Rached-ozz961/WinPingSweeper.git
    cd WinPingSweeper
    ```

2. Install required libraries:

    ```bash
    pip install -r requirements.txt
    ```

3. Ensure `arp-ping.exe` is in your path.

## Usage

### Option 1: Python

1. Run:

    ```bash
    python WinPingSweeper.py
    ```

2. Choose scan type (ICMP, ARP, or both) and IP range.

### Option 2: `run.bat`

1. Simply double-click `run.bat` to execute.

## Results

- Results are saved in the `Active_Hosts` folder with filenames like:
    ```
    icmp_active_hosts_YYYY-MM-DD_HH-MM-SS.txt
    arp_active_hosts_YYYY-MM-DD_HH-MM-SS.txt
    ```

## Contributing

1. Fork the repo, create a branch, make changes, and submit a pull request.

## License

MIT License

## Author

- **Roger Rached**
