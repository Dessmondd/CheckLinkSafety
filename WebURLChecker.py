import os
import requests


url_tocheck = input("Please, provide the website or link to check: ")

def url_checker(url_tocheck):
    api_key="APIKEY"
    params = {'apikey': api_key, 'resource': url_tocheck}
    headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip, My Python requests library"
    }
    response = requests.get(url_tocheck, params, headers=headers)
    response_json = response.json()
    if response_json['response_code'] == 0:
        print("Link is not malicious, you are safe!")
        return False
    if response_json['positives'] == 1:
        # URL it's malicious based on at least ONE 
        return True
    else: 
        print("It's not malicious.")

