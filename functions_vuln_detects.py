import requests
import credentials
import json


def get_vulners_linux_audit_data(os_data):
    # data = {"os": "debian", "version": "10", "package": <package_list>, "apiKey": token}
    if credentials.vulners_api_key == "":
        print("Error: No Vulners API key")
        exit()
    if os_data["os_name"] not in ['ubuntu', 'debian', 'centos', 'oraclelinux', 'redhat', 'fedora', 'alpine']:
        print("Error: Unsupported OS (" + os_data["os_name"] + ")")
        exit()
    data = {"os": os_data["os_name"], "version": os_data["os_version"],
            "package": os_data["package_list"], "apiKey": credentials.vulners_api_key}
    headers = {
        'User-Agent': 'Scanvus v1.0.3',
    }
    response = requests.post('https://vulners.com/api/v3/audit/audit', data=json.dumps(data), headers=headers)
    vulners_data = response.json()
    if vulners_data['result'] == "error":
        print("Error: " + vulners_data['data']['error'] + " (" +  str(vulners_data['data']['errorCode']) + ")" )
        exit()
    return vulners_data
