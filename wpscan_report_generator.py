import json
import sys
import os  # Import os module to handle file paths
from jinja2 import Template

# Function to parse vulnerabilities, plugins, and other important info
def parse_wpscan_data(data):
    report_data = {
        "target_url": data.get("target_url", "N/A"),
        "start_time": data.get("start_time", "N/A"),
        "stop_time": data.get("stop_time", "N/A"),
        "plugins": data.get("plugins", {}),
        "main_theme": data.get("main_theme", {}),
        "interesting_findings": data.get("interesting_findings", []),
        "vulnerabilities": [],
        "users": []
    }

    # Extract vulnerabilities and plugin info

    users = data.get("users", [])

    if users:
        for user in users:
            user_data = {
                "username": user}

            report_data["users"].append(user_data)  

    for plugin, details in data.get("plugins", {}).items():
        vulnerabilities = details.get("vulnerabilities", [])
        version_info = details.get("version", {})

        # Check if version_info is not None and extract interesting entries
        interesting_entries = version_info.get("interesting_entries", []) if version_info else []

        plugin_data = {
            "plugin": plugin,
            "location": details.get("location", "N/A"),
            "latest_version": details.get("latest_version", "N/A"),
            "outdated": details.get("outdated", "N/A"),
            "confidence": details.get("confidence", "N/A"),
            "interesting_entries": interesting_entries,
            "vulnerabilities": []
        }

        # Parse vulnerabilities for the plugin
        for vuln in vulnerabilities:
            plugin_data["vulnerabilities"].append({
                "title": vuln.get("title", "N/A"),
                "references": vuln.get("references", {}).get("url", []),
            })

        report_data["vulnerabilities"].append(plugin_data)

    return report_data

# Function to create HTML report with colors, Interesting Findings, References, and Interesting Entries
def create_html_report(data, output_file_name):
    template_str = """
    <html>
    <head>
        <title>WPScan Report</title>
        <style>
            .green { color: green; }
            .dark-blue { color: darkblue; }
            .orange { color: orange; }
            .red { color: red; }
        </style>
    </head>
    <body>
        <h1>WPScan Report</h1>
        <h2>Target URL: {{ target_url }}</h2>
        <p>Start Time: {{ start_time }}</p>
        <p>Stop Time: {{ stop_time }}</p>

        <h3>Interesting Finding(s)</h3>
        <ul>
        {% for finding in interesting_findings %}
            <li><strong>{{ finding.to_s }}:</strong> {{ finding.url }}</li>
        {% endfor %}
        </ul>
        
        <h3>Main Theme Information</h3>
        <p>Theme: {{ main_theme.slug }}</p>
        <p>Version: {{ main_theme.version.number if main_theme.version else 'N/A' }}</p>

        <h3>Plugin Information</h3>
        <ul>
        {% for plugin in vulnerabilities %}
            <li><strong>{{ plugin.plugin }}:</strong>
                <ul>
                    <li>Location: {{ plugin.location }}</li>
                    <li>Latest Version: {{ plugin.latest_version }}</li>
                    <li>Outdated: <span class="{{ 'red' if plugin.outdated else 'green' }}">{{ plugin.outdated }}</span></li>
                    <li>Confidence: <span class="{{ 
                        'green' if plugin.confidence == 100 else 
                        'dark-blue' if plugin.confidence >= 50 and plugin.confidence <= 90 else 
                        'orange' }}">{{ plugin.confidence }}</span></li>

                    <li>Interesting Entries:</li>
                    <ul>
                    {% for entry in plugin.interesting_entries %}
                        <li>{{ entry }}</li>
                    {% endfor %}
                    </ul>
                    
                    <li>Vulnerabilities:
                        <ul>
                        {% for vuln in plugin.vulnerabilities %}
                            <li><span class="red">{{ vuln.title }}</span>
                                <ul>
                                    <li>References:</li>
                                    <ul>
                                    {% for ref in vuln.references %}
                                        <li><a href="{{ ref }}">{{ ref }}</a></li>
                                    {% endfor %}
                                    </ul>
                                </ul>
                            </li>
                        {% endfor %}
                        </ul>
                    </li>
                </ul>
            </li>
        {% endfor %}
        </ul>
        {%if users %}
        <h3>Users found</h3>
        <ul>
        {% for user in users %}
            <li>{{ user.username }}</li>
        {% endfor %}
        </ul>
        {% endif %}
    </body>
    </html>
    """
    template = Template(template_str)
    html_content = template.render(data)
    
    # Save to HTML file
    with open(output_file_name, 'w') as html_file:
        html_file.write(html_content)
    
    return output_file_name

# Main execution to handle dynamic JSON file input
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python wpscan_report_generator.py <path_to_json_file>")
        sys.exit(1)

    # Load the specified JSON file
    json_file_path = sys.argv[1]
    with open(json_file_path, 'r') as file:
        wpscan_data = json.load(file)

    # Parse the JSON data
    report_data = parse_wpscan_data(wpscan_data)

    # Generate HTML report with the same name as the input file
    base_name = os.path.splitext(os.path.basename(json_file_path))[0]
    html_report_name = f"{base_name}.html"
    html_report = create_html_report(report_data, html_report_name)

    print(f"HTML Report generated: {html_report}")

