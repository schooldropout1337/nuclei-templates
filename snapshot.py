import requests
import hashlib
from datetime import datetime
import sys
from urllib.parse import urlparse

def generate_logfile_name(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.replace(".", "-")
    path = parsed_url.path.replace("/", "-").strip("-")
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{domain}{path}.{timestamp}.txt"

def parse_headers(header_lines):
    headers = {}
    for line in header_lines.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers

def main(url, headers=None):
    try:
        # Fetch the webpage with custom headers
        response = requests.get(url, headers=headers)

        # Get current timestamp
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        if response.status_code == 200:
            # Get the content length from the response header
            content_length = response.headers.get('content-length')

            # Calculate MD5 checksum of response body
            md5_hash = hashlib.md5(response.content).hexdigest()

            # Generate logfile name based on domain and path
            logfile_name = generate_logfile_name(url)

            # Save response body and MD5 checksum to the logfile
            with open(logfile_name, "w") as output_file:
                output_file.write(f"URL: {url}\n\n")
                output_file.write(f"Content Length: {content_length}\n\n")
                output_file.write("Response Body:\n")
                output_file.write(response.text + "\n\n")
                output_file.write("MD5 Checksum:\n")
                output_file.write(md5_hash)
            
            print("Data saved successfully to", logfile_name)
        else:
            print("Failed to fetch webpage:", response.status_code)
    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python snapshot.py url -H \"Header: value\" -H \"Cookie: cookie=monster\"")
        sys.exit(1)

    url = sys.argv[1]
    headers = {}
    # Parse custom headers if provided
    if "-H" in sys.argv:
        header_index = sys.argv.index("-H")
        header_lines = "\n".join(sys.argv[header_index + 1:])
        headers = parse_headers(header_lines)

    main(url, headers=headers)

