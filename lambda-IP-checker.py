#!/usr/bin/env python3

"""
Purpose:
    This script takes a IP address as input, queries VT API about the IP, and
    prepares and serves up the returning YAML data
"""

import os
import requests
import time
import json

apikey = os.getenv('VT_API_KEY')
# ip = '24.18.229.223'
# ip = '88.80.26.2'
# url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
# headers = {"x-apikey": apikey}

all_IPs = [
    # '24.18.229.223',
    '88.80.26.2',
    # '66.249.70.104',
    # '66.249.70.105',
    # '66.249.70.106',
    '5.79.212.230'
]


def rate_limited_api_call(
        api_arg,
        api_url='https://www.virustotal.com/api/v3/ip_addresses/',
        api_key=os.environ.get('VT_API_KEY'),
        rate_limit=4,  # per minute
        max_retries=3,
        ):
    """
    Make an API call, respecting the rate limit.
    """
    headers = {"x-apikey": api_key}
    url = f'{api_url}{api_arg}'
    # current_time = time.time()
    attempt = 0

    while attempt < max_retries:
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                time.sleep(60 / rate_limit)
                return response
            elif response.status_code == 429:
                print("Rate limit exceeded. Retrying after 60 seconds...")
                time.sleep(60)
            else:
                # Log non-200 responses for debugging
                print(f"Error {response.status_code}: {response.text}")
                return None
        except requests.exceptions.Timeout:
            print("Request timed out. Retrying...")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

# def main():
#     """"""
#     response = requests.get(url, headers=headers)
#     result = response.json()
#     # print(type(result))
#     # print(result)

#     filtered_result = {
#         "IP": result.get("data", {}).get("id"),
#         "Last Analysis Stats": result.get("data",{}).get("attributes", {}).get("last_analysis_stats"),
#     }
#     print(filtered_result)

#     malicious_score = filtered_result['Last Analysis Stats']['malicious']

#     print(malicious_score)


def main():
    """"""
    # ip = '88.80.26.2'
    malicicious_IP_data = []

    for ip in all_IPs:
        response = rate_limited_api_call(ip)
        # print(type(response))
        data = response.json()
        filtered_data = {
            "IP": data.get("data", {}).get("id"),
            "Last Analysis Stats": data.get("data",{}).get("attributes", {}).get("last_analysis_stats"),
        }
        # print(filtered_data)
        malicious_score = filtered_data['Last Analysis Stats']['malicious']
        if malicious_score > 0:
            malicicious_IP_data.append(filtered_data)

    print(malicicious_IP_data)
    for data in malicicious_IP_data:
        formatted_data = json.dumps(data, indent=4)
        print(formatted_data)

    # with open("output.json", "w") as file:
        # json.dump(data, file, indent=4)
        # print("JSON data has been written to output.json")

    # all_results = []
    # for ip in all_IPs:
    #     # api_url_get = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    #     # response = requests.get(api_url_get, headers=headers)
    #     response = rate_limited_api_call(ip)
    #     result = response #.json()
    #     all_results.append(result)
    # print(all_results)

    print("Done")

if __name__ == "__main__":
    main()
