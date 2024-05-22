import requests
from bs4 import BeautifulSoup
import argparse
import re
import socket
from urllib.parse import urlparse, urljoin

# Regular expression to match domains ending with valid TLDs
# This regex is not perfect, double check results with httpx 
tld_regex = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:dev|stg|prod|local|com|net|org|edu|gov|mil|co|us|uk|io|info|biz|me|tv|ca|de|fr|jp|au|in|it|nl|ru|br|mx|es|se|ch|za|be|pl|gr|kr|tw|hk|at|cz|pt|tr|vn|id|hu|ar|ro|bg|sk|cl|fi|no|nz|my|sg|th|pk|ae|sa|ua|il|ie|dk|hk|si|lt|ee|lv|cy|lu|is|mt|md|ba|hr|mk|al|rs|li|fo|sm|je|gg|im|ax|gl|gf|pf|nc|tf|pm|yt|wf|bl|mf|gp|mq|re|fr)\b'
)

# Regular expression to match IP addresses
ip_regex = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

# Regular expression to detect leaked credentials in JS
leak_creds_regex = re.compile(
        r'(?i)((api_key|username|password|access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,@]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}["\']([0-9a-zA-Z\-_=@!#\$%\^&\*\(\)\+\[\]\{\}\|;:,<>\?~`]{1,64})["\']'
)

# Regular expression to extract cookies from JavaScript
cookie_regex = re.compile(r'document\.cookie\s*=\s*["\']([^"\']+)["\'];', re.IGNORECASE)

# Regular expression to extract localStorage entries from JavaScript
local_storage_regex = re.compile(r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE)


def extract_data(url, headers):
    try:

        print(f"\nLazyEgg\n")
        # Sending a GET request to the URL with the supplied headers
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx and 5xx)

        # Parsing the HTML content of the page
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extracting links
        links = [urljoin(url, link.get('href')) for link in soup.find_all('a') if link.get('href')]

        # Extracting image URLs
        images = [urljoin(url, img.get('src')) for img in soup.find_all('img') if img.get('src')]

        # Extracting cookies
        cookies = response.cookies
        cookie_strings = [f"{cookie.name}={cookie.value}" for cookie in cookies]

        # Extracting forms and inputs
        forms = []
        for form in soup.find_all('form'):
            form_data = {'action': form.get('action'), 'method': form.get('method'), 'inputs': []}
            for input_tag in form.find_all('input'):
                input_data = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type'),
                    'value': input_tag.get('value'),
                }
                form_data['inputs'].append(input_data)
            forms.append(form_data)

        # Extracting JS URLs/domains/subdomains/IPs
        scripts = [urljoin(url, script.get('src')) for script in soup.find_all('script') if script.get('src')]
        js_urls = set()  # Using a set to avoid duplicate entries
        leaked_creds = []
        Oxcookies = []
        local_storage = []
        for script in scripts:
            try:
                js_response = requests.get(script, headers=headers)
                js_response.raise_for_status()
                js_content = js_response.text

                # Extract URLs that start with http or https
                js_urls.update(re.findall(r'https?://[^\s\'"<>]+', js_content))

                # Extract domains, subdomains, and IP addresses
                potential_domains = re.findall(tld_regex, js_content)
                potential_ips = re.findall(ip_regex, js_content)
                js_urls.update(potential_domains)
                js_urls.update(potential_ips)

                # Find leaked credentials
                leaked_creds.extend(leak_creds_regex.findall(js_content))
                # Extracting cookies
                Oxcookies = cookie_regex.findall(js_content)

                # Extracting localStorage entries
                local_storage = local_storage_regex.findall(js_content)

            except requests.RequestException as e:
                print(f"Warning: Could not fetch {script}: {e}")

        return links, images, cookie_strings, forms, list(js_urls), leaked_creds, Oxcookies, local_storage

    except requests.ConnectionError:
        print("Abort - Connection Error")
        exit(1)
    except requests.HTTPError as http_err:
        print(f" HTTP error occurred: {http_err}")
        exit(1)
    except Exception as err:
        print(f" An error occurred: {err}")
        exit(1)

def check_open_ports(domain, url_port):
    ports = [
        80, 443, 1194, 1723, 1701, 500, 4500, 3000, 3001, 8080, 8443, 9990,
        8085, 8000, 8081, 8181, 8888, 9200, 9300, 6379, 3306, 5432, 1433,
        1521, 27017, 9042, 11211
    ]
    open_ports = []

    # Exclude the URL's port if provided
    if url_port:
        try:
            url_port = int(url_port)
            if url_port in ports:
                ports.remove(url_port)
        except ValueError:
            pass

    try:
        ip = socket.gethostbyname(domain)
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
    except socket.gaierror as e:
        print(f"Abort: Port Scanning Error - {e}")
        exit(1)
    except Exception as e:
        print(f"Abort: Port Scanning Error - {e}")
        exit(1)

    return open_ports

if __name__ == "__main__":
    try:
        # Parsing command-line arguments
        parser = argparse.ArgumentParser(description="LazyEgg extracts links, images, cookies, forms, JS URLs, localStorage, Host, IP, and leaked credentials from target.")
        parser.add_argument("url", help="URL to extract data from")
        parser.add_argument("-H", "--header", help="Headers in the format 'key: value'", action='append')

        args = parser.parse_args()

        headers = {}
        if args.header:
            for header in args.header:
                key_value = header.split(':', 1)  # Ensure split only at the first colon
                if len(key_value) == 2:
                    headers[key_value[0].strip()] = key_value[1].strip()
                else:
                    print("Invalid header format:", header)
                    exit(1)

        parsed_url = urlparse(args.url)
        domain = parsed_url.hostname
        url_port = parsed_url.port

        links, images, cookies, forms, js_urls, leaked_creds, Oxcookies, local_storage = extract_data(args.url, headers)
        open_ports = check_open_ports(domain, url_port)

        print("\033[1m\033[33m Links:\033[37m\033[22m")
        for link in links:
            print(link)

        print("\n\033[1m\033[33m Images:\033[37m\033[22m")
        for img in images:
            print(img)

        print("\n\033[1m\033[33m Cookies:\033[37m\033[22m")
        for cookie in cookies:
            print(cookie)

        print("\n\033[1m\033[33m JS 0xCookies:\033[37m\033[22m")
        for Oxcookie in Oxcookies:
            print(Oxcookie)

        print("\n\033[1m\033[33m Forms and Inputs:\033[37m\033[22m")
        for form in forms:
            print(f"Form action: {form['action']}, method: {form['method']}")
            for input_tag in form['inputs']:
                print(f"  Input name: {input_tag['name']}, type: {input_tag['type']}, value: {input_tag['value']}")

        print("\n\033[1m\033[33m JS URLs/Host/IPs:\033[37m\033[22m")
        for js_url in js_urls:
            print(js_url)

        print("\n\033[1m\033[33m JS Leaked Credentials:\033[37m\033[22m")
        for leaked_cred in leaked_creds:
            print(leaked_cred)

        print("\n\033[1m\033[33m JS localStorage:\033[37m\033[22m")
        for localStorage in local_storage:
            print(localStorage)

        print("\n\033[1m\033[33m Open Ports:\033[37m\033[22m")
        for port in open_ports:
            print(port)

        print(f"\nLazyEgg\n")

    except KeyboardInterrupt:
        print("\nProgram interrupted.  Exiting gracefully.")
        exit(0)

