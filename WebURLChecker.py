import os
import requests

VIRUSTOTAL_API_KEY = "YOUR_API_KEY"

def file_checker(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()

    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    files = {
        "file": (os.path.basename(file_path), file_data)
    }
    response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        json_response = response.json()
        data = json_response["data"]
        attributes = data["attributes"]
        results = attributes["last_analysis_results"]
        positives = sum(1 for result in results.values() if result["category"] == "malicious")
        if positives > 0:
            return True
        else:
            return False
    else:
        raise Exception(f"File scan failed with status code {response.status_code}")


def url_checker(url_tocheck):
    url = "https://www.virustotal.com/api/v3/urls"
    params = {
        "url": url_tocheck
    }
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, params=params, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        data = json_response["data"]
        attributes = data["attributes"]
        categories = attributes["categories"]
        if "malicious" in categories:
            return True
        else:
            return False
    else:
        raise Exception(f"URL scan failed with status code {response.status_code}")


def scanner(file_or_url):
    if os.path.isfile(file_or_url):
        return file_checker(file_or_url)
    else:
        return url_checker(file_or_url)