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


def get_vulnsio_linux_audit_data(os_data):
    if credentials.vulnsio_api_key == "":
        print("Error: No Vulns.io API key")
        exit()

    if os_data["os_name"] not in ['ubuntu', 'debian', 'centos', 'oracle', 'redhat', 'alpine', 'virtuozzo', 'rocky', 'amazon', 'redos']:
        print("Error: Unsupported OS (" + os_data["os_name"] + ")")
        exit()

    payload = {
        "os": {
            "id": os_data["os_name"],
            "version": os_data["os_version"]
            },
        "packages": os_data["package_list"]
    }

    headers = {
        "x-api-key": credentials.vulnsio_api_key,
        "User-Agent": "Scanvus v1.0.3",
    }

    try:
        response = requests.post('https://api.vulns.io/common/v1/audit/linux/packages/', json=payload, headers=headers, timeout=30)
        vulnsio_data = response.json()
    except Exception as e:
        print(f"Error while making request to Vulns.io API: {e}")
        exit()

    if response.status_code != 200:
        print(f"Error: {vulnsio_data['code']} ({vulnsio_data['message']})")
        exit()

    return vulnsio_data
