# Log Analysis System

## Overview
A robust log analysis tool that processes web server logs to identify patterns, potential security threats, and usage statistics. The system generates both CSV and HTML reports for easy data visualization and analysis.

## Key Features
- **IP Traffic Analysis**: Tracks and summarizes request frequency per IP address
- **Endpoint Monitoring**: Identifies the most frequently accessed endpoints
- **Security Analysis**: Detects suspicious activity based on failed login attempts
- **Multiple Output Formats**: 
  - Interactive HTML reports with sortable tables
  - CSV exports for data processing
  - Terminal output for quick viewing

## Technical Implementation
- Built in Python using standard libraries and minimal dependencies
- Implements efficient data processing using Counter collections
- Uses regex pattern matching for accurate log parsing
- Generates responsive HTML reports with modern CSS styling

## Sample Output
The system generates three types of analysis:

1. **Requests Per IP**: Shows traffic distribution across different IP addresses
2. **Popular Endpoints**: Identifies most accessed URLs/endpoints
3. **Security Alerts**: Flags IPs with suspicious activity (e.g., multiple failed logins)

## Setup and Installation

### Prerequisites
- Python 3.6 or higher
- Git (optional, for cloning)

### Installation Steps
1. **Get the Code**:
   ```
   # Option 1: Clone with Git
   git clone https://github.com/vignesh3022/VRV-Security-Python-Intern-Assignment.git
   cd log-analysis-system

   # Option 2: Download ZIP
   # Download and extract the ZIP file from the repository
   ```

2. **Install Dependencies**:
   ```
   pip install prettytable
   ```

## How to Use

### Input
- The system processes web server logs in the standard Apache/Nginx format
- Sample data is provided in `sample.log` for testing and demonstration
- You can replace `sample.log` with your own log file following the same format

### Processing
1. Place your log file in the project directory
2. Run the analysis script:
   ```
   python log_analysis.py
   ```
3. The script (`log_analysis.py`) processes the log file and performs:
   - Request frequency analysis
   - Endpoint usage tracking
   - Security threat detection

### Output Options
1. **Browser View**: 
   - Open `log_analysis_report.html` in any web browser or you can use this command in terminal to start the browser: `start log_analysis_report.html`

2. **CSV Export**:
   - Check `log_analysis_results.csv` for raw data
   - Suitable for further data processing or spreadsheet analysis

3. **Terminal Output**:
   - Immediate results displayed in console
   - Quick overview of key metrics
