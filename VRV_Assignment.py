import re
import csv
from collections import defaultdict

# Constants
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
CSV_OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    """Parse the log file and yield log entries."""
    with open(file_path, 'r') as file:
        for line in file:
            yield line.strip()

def count_requests_per_ip(log_lines):
    """Count the number of requests per IP address."""
    ip_counts = defaultdict(int)
    for line in log_lines:
        # Regex to extract IP address
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_counts[ip] += 1
    return ip_counts

def identify_most_accessed_endpoint(log_lines):
    """Identify the most frequently accessed endpoint."""
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        # Regex to extract the endpoint
        match = re.search(r'\"[A-Z]+\s(/[\w/]+)\s', line)
        if match:
            endpoint = match.group(1)
            endpoint_counts[endpoint] += 1

    if endpoint_counts:
        most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
        return most_accessed
    return None

def detect_suspicious_activity(log_lines, threshold=FAILED_LOGIN_THRESHOLD):
    """Detect suspicious activity based on failed login attempts."""
    failed_login_counts = defaultdict(int)
    for line in log_lines:
        # Regex to detect failed login (e.g., 401 status or "Invalid credentials")
        if "401" in line or "Invalid credentials" in line:
            # Extract the IP address for the failed login attempt
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                failed_login_counts[ip] += 1

    # Filter out IPs that have failed login attempts exceeding the threshold
    suspicious_ips = {ip: count for ip, count in failed_login_counts.items() if count > threshold}
    return suspicious_ips

def display_results(ip_counts, most_accessed_endpoint, suspicious_ips):
    """Display the results in a readable format."""
    # Display IP request counts
    print("### Request Counts per IP Address ###")
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    # Display the most frequently accessed endpoint
    if most_accessed_endpoint:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Display suspicious activity
    print("\n### Suspicious Activity ###")
    if suspicious_ips:
        print("Suspicious IPs (Failed Login Attempts Exceeding Threshold):")
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips, output_file=CSV_OUTPUT_FILE):
    """Save the analysis results to a CSV file."""
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        if most_accessed_endpoint:
            writer.writerow([])
            writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    """Main function to perform log analysis."""
    log_lines = list(parse_log_file(LOG_FILE))
    
    # Task 1: Count Requests per IP Address
    ip_counts = count_requests_per_ip(log_lines)
    
    # Task 2: Identify the Most Frequently Accessed Endpoint
    most_accessed_endpoint = identify_most_accessed_endpoint(log_lines)
    
    # Task 3: Detect Suspicious Activity (Failed Login Attempts)
    suspicious_ips = detect_suspicious_activity(log_lines, FAILED_LOGIN_THRESHOLD)
    
    # Display results on the terminal
    display_results(ip_counts, most_accessed_endpoint, suspicious_ips)
    
    # Save results to a CSV file
    save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips)

if __name__ == "__main__":
    main()
