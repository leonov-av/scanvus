import requests
import credentials
import json


def get_vulners_linux_audit_data(os_data):
    # data = {"os": "debian", "version": "10", "package": <package_list>, "apiKey": token}
    if credentials.vulners_api_key == "":
        print("Error: No Vulners API key")
        exit()
    data = {"os": os_data["os_name"], "version": os_data["os_version"],
            "package": os_data["package_list"], "apiKey": credentials.vulners_api_key}
    response = requests.post('https://vulners.com/api/v3/audit/audit', data=json.dumps(data))
    return response.json()
