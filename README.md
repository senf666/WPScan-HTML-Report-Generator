# WPScan-HTML-Report-Generator
A Python tool that converts WPScan JSON output files into clear, color-coded HTML reports. The report includes vulnerabilities, interesting findings, plugin details, and references for easy review.


## Features
- Parses WPScan JSON output.
- Generates an HTML report with color-coded confidence and outdated statuses.
- Displays vulnerabilities, references, and interesting entries.

## Dependencies
- wpscan
- Python 3.x
- Jinja2 (for templating)

### Install dependencies:
```bash
pip install jinja2
```

## Usage
1. Run the script by specifying the WPScan JSON file:
```bash
python wpscan_report_generator.py <path_to_json_file>
```
2. The HTML report will be generated as `wpscan_report.html.`
