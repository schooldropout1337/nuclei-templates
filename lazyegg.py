import requests
from bs4 import BeautifulSoup
import argparse

def extract_data(url, headers):
    try:
        # Sending a GET request to the URL with the supplied headers
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx and 5xx)

        # Parsing the HTML content of the page
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extracting links
        links = [link.get('href') for link in soup.find_all('a') if link.get('href')]

        # Extracting image URLs
        images = [img.get('src') for img in soup.find_all('img') if img.get('src')]

        # Extracting cookies
        cookies = response.cookies
        cookie_strings = [f"{cookie.name}={cookie.value}" for cookie in cookies]

        return links, images, cookie_strings

    except requests.ConnectionError:
        print("Abort - Connection Error")
        exit(1)
    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        exit(1)
    except Exception as err:
        print(f"An error occurred: {err}")
        exit(1)

if __name__ == "__main__":
    try:
        # Parsing command-line arguments
        parser = argparse.ArgumentParser(description="🥚LazyEgg🥚 extracts links, images, and cookies from a given URL.")
        parser.add_argument("url", help="URL to extract data from")
        parser.add_argument("-H", "--header", help="Headers in the format 'key:value'", action='append')

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

        # Debug print to check headers
        # print("Headers to be sent:", headers)

        links, images, cookies = extract_data(args.url, headers)

        print("\033[1m\033[33m🐣Links:\033[37m\033[22m")
        for link in links:
            print(link)

        print("\n\033[1m\033[33m🐣Images:\033[37m\033[22m")
        for img in images:
            print(img)

        print("\n\033[1m\033[33m🐣Cookies:\033[37m\033[22m")
        for cookie in cookies:
            print(cookie)

    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting gracefully. Enhance module with ChatGPT.")
        exit(0)

