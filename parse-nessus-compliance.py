import xml.etree.ElementTree as ET
import csv
import sys
from collections import defaultdict

def parse_nessus(file_path, output_csv):
    # Parse the Nessus file
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Dictionary to group issues by title
    compliance_issues = defaultdict(lambda: {"Policy Description": "", "Setting on Host": "", "Recommended Setting": "", "Hosts": set()})

    # Iterate through the 'ReportItem' elements
    for report_host in root.findall("Report/ReportHost"):
        host_name = report_host.attrib.get("name")
        for report_item in report_host.findall("ReportItem"):
            plugin_id = report_item.attrib.get("pluginID")
            
            # Focus on compliance checks
            if plugin_id == "21156":  # The typical plugin ID for compliance checks
                compliance_result = report_item.findtext("cm:compliance-result", default="", namespaces={"cm": "http://www.nessus.org/cm"})
                if compliance_result in ["FAILED", "WARNING"]:
                    title = report_item.findtext("cm:compliance-check-name", default="", namespaces={"cm": "http://www.nessus.org/cm"})
                    policy_description = report_item.findtext("cm:compliance-info", default="", namespaces={"cm": "http://www.nessus.org/cm"})
                    setting_on_host = report_item.findtext("cm:compliance-actual-value", default="", namespaces={"cm": "http://www.nessus.org/cm"})
                    recommended_setting = report_item.findtext("cm:compliance-policy-value", default="", namespaces={"cm": "http://www.nessus.org/cm"})

                    # Group by title and consolidate affected hosts
                    compliance_issues[title]["Policy Description"] = policy_description
                    compliance_issues[title]["Setting on Host"] = setting_on_host
                    compliance_issues[title]["Recommended Setting"] = recommended_setting
                    compliance_issues[title]["Hosts"].add(host_name)

    # Prepare data for CSV
    sorted_issues = sorted(compliance_issues.items())
    with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Title", "Policy Description", "Setting on Host", "Recommended Setting", "Affected Hosts"])  # Header row
        for title, details in sorted_issues:
            writer.writerow([
                title,
                details["Policy Description"],
                details["Setting on Host"],
                details["Recommended Setting"],
                "; ".join(sorted(details["Hosts"]))  # Join hosts into a single string
            ])

    print(f"Results written to {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python parse_nessus.py <input_nessus_file> <output_csv_file>")
        sys.exit(1)

    # Read file paths from the command line
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        parse_nessus(input_file, output_file)
    except Exception as e:
        print(f"An error occurred: {e}")
