import xml.etree.ElementTree as ET
import csv
import argparse

def parse_nessus_file(nessus_file, output_csv):
    # Parse the .nessus XML file
    tree = ET.parse(nessus_file)
    root = tree.getroot()

    # Define severity levels of interest
    severity_levels = {4: "Critical", 3: "High", 2: "Medium"}

    # Prepare a list for storing extracted data
    extracted_data = []

    # Iterate through each report item in the .nessus file
    for report in root.findall(".//Report"):
        for report_host in report.findall("ReportHost"):
            host = report_host.get("name")
            for report_item in report_host.findall("ReportItem"):
                severity = int(report_item.get("severity", 0))
                if severity in severity_levels:
                    title = report_item.get("pluginName", "Unknown")
                    cvss_score = report_item.findtext("cvss_base_score", "N/A")
                    cve_elements = report_item.findall("cve")
                    cve = ", ".join(cve.text for cve in cve_elements) if cve_elements else ""
                    extracted_data.append({
                        "title": title,
                        "severity": severity_levels[severity],
                        "cvss_score": cvss_score,
                        "cve": cve,
                        "host": host,
                    })

    # Aggregate hosts by vulnerability
    aggregated_data = {}
    for item in extracted_data:
        key = (item["title"], item["severity"], item["cvss_score"], item["cve"])
        if key not in aggregated_data:
            aggregated_data[key] = []
        aggregated_data[key].append(item["host"])

    # Write the data to a CSV file
    with open(output_csv, "w", newline="") as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Title", "Severity", "CVSS Score", "CVE", "Hosts Affected"])
        for (title, severity, cvss_score, cve), hosts in aggregated_data.items():
            csvwriter.writerow([title, severity, cvss_score, cve, ", ".join(hosts)])

    print(f"Data successfully written to {output_csv}")

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Parse a .nessus file and generate a CSV report.")
    parser.add_argument("nessus_file", help="Path to the .nessus file")
    parser.add_argument("-o", "--output", default="missing_patches_with_cve.csv",
                        help="Path to the output CSV file (default: missing_patches_with_cve.csv)")

    args = parser.parse_args()

    # Run the parser with the provided arguments
    parse_nessus_file(args.nessus_file, args.output)
