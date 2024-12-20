import xml.etree.ElementTree as ET
import sys
from collections import defaultdict

def parse_nessus(file_path, output_file):
    # Parse the Nessus file
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Define severity mapping
    severity_map = {2: "Medium", 3: "High", 4: "Critical"}

    # Dictionary to collect issues
    issues = defaultdict(lambda: {"Severity": "", "Hosts": defaultdict(list)})

    # Iterate through the 'ReportHost' elements
    for report_host in root.findall("Report/ReportHost"):
        host_name = report_host.attrib.get("name")
        for report_item in report_host.findall("ReportItem"):
            plugin_id = report_item.attrib.get("pluginID")
            severity = int(report_item.attrib.get("severity", "0"))

            # Filter for medium, high, and critical issues that are not patches or compliance checks
            if severity in severity_map and plugin_id not in ["21156", "19506"]:  # Exclude compliance (21156) and patch checks (19506)
                title = report_item.attrib.get("pluginName", "Unknown Title")
                evidence = report_item.findtext("plugin_output", "").strip()

                # Add issue details
                issues[title]["Severity"] = severity_map[severity]
                issues[title]["Hosts"][host_name].append(evidence or "No evidence provided")

    # Write the results to the output file
    with open(output_file, "w", encoding="utf-8") as outfile:
        for title, details in issues.items():
            outfile.write(f"Issue Title: {title}\n")
            outfile.write(f"Severity: {details['Severity']}\n")

            for host, evidences in details["Hosts"].items():
                outfile.write(f"Affected Host: {host}\n")
                outfile.write("Evidence:\n")
                for evidence in evidences:
                    outfile.write(f"- {evidence}\n")

            outfile.write("===========================================\n")

    print(f"Results written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python parse_nessus_issues.py <input_nessus_file> <output_file>")
        sys.exit(1)

    # Read file paths from the command line
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        parse_nessus(input_file, output_file)
    except Exception as e:
        print(f"An error occurred: {e}")
