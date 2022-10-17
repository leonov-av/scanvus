import functions_transport_ssh
import functions_linux_inventory
import functions_vuln_detects
import functions_reports
import functions_transport_localhost
import functions_transport_docker
import argparse
import json

def get_text_block(target):
    temp_text_block = ""
    bash_script_oneliner = functions_linux_inventory.get_bash_script_oneliner(functions_linux_inventory.linux_audit_bash_script)
    if target["assessment_type"] == "remote_ssh":
        ssh_client = functions_transport_ssh.get_ssh_client(target)
        command_result = functions_transport_ssh.execute_command(ssh_client, command=bash_script_oneliner)
        functions_transport_ssh.close_ssh_client(ssh_client)
        if command_result['errors'] != "":
            print("Error: SSH command " + command_result['errors'])
            exit()
        else:
            temp_text_block = command_result['output']
    elif target["assessment_type"] == "localhost":
        temp_text_block = functions_transport_localhost.execute_command(command=bash_script_oneliner)
    elif target["assessment_type"] == "docker_image":
        try:
            temp_text_block = functions_transport_docker.execute_command_docker_expect(
                                                                docker_name=target["docker_image"],
                                                                command=bash_script_oneliner)
        except:
            temp_text_block = ""
        if not "=========  END  =========" in temp_text_block:
            print("Problems with docker_expect, trying alternative docker image audit...")
            temp_text_block = functions_transport_docker.get_linux_audit(docker_name=target["docker_image"])

    elif target["assessment_type"] == "inventory_file":
        f = open(target["inventory_file"],"r")
        temp_text_block = f.read()
        f.close()

    temp_text_block = functions_linux_inventory.clear_text_block(temp_text_block)
    return temp_text_block


def get_os_data_dict(text_block):
    os_data = dict()
    os_data["os_name"] = functions_linux_inventory.get_os_name_from_text_block(text_block)
    os_data["os_version"] = functions_linux_inventory.get_os_version_from_text_block(text_block)
    os_data["linux_kernel"] = functions_linux_inventory.get_linux_kernel_from_text_block(text_block)
    os_data['package_list'] = functions_linux_inventory.get_os_packages_from_text_block(text_block)
    # os_data['package_list'] = ["apt 1.0.6 amd64","apt-config-icons 0.12.10-2 all"] # DEBUG
    return os_data

parser = argparse.ArgumentParser(description='Scanvus is a Simple Credentialed Authenticated Network VUlnerability Scanner for Linux systems and docker images')
parser.add_argument('--assessment-type', help='Assessment type (E.g.: remote_ssh, localhost, docker_image, inventory_file)')
parser.add_argument('--host', help='Remote host to scan (ip of hostname)')
parser.add_argument('--user-name', help='Username to authenticate on remote host')
parser.add_argument('--password', help='Password to authenticate on remote host')
parser.add_argument('--key-path', help='Path to the private key file to authenticate on remote host')
parser.add_argument('--docker-image', help='Docker image')
parser.add_argument('--show-inventory-script', help='Shows inventory bash oneliner', action="store_true")
parser.add_argument('--inventory-file-path', help='Inventory file to process')
parser.add_argument('--save-os-data-text-block-path', help='Path to the OS data Text Block result file')
parser.add_argument('--save-os-data-json-path', help='Path to the OS data JSON result file')
parser.add_argument('--save-vuln-raw-json-path', help='Path to the Raw Vulnerability data JSON result file')
parser.add_argument('--save-vuln-report-json-path', help='Path to the Vulnerability Report data JSON result file')

print('''  /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$    /$$/$$   /$$  /$$$$$$$
 /$$_____/ /$$_____/ |____  $$| $$__  $$|  $$  /$$/ $$  | $$ /$$_____/
|  $$$$$$ | $$        /$$$$$$$| $$  \ $$ \  $$/$$/| $$  | $$|  $$$$$$ 
 \____  $$| $$       /$$__  $$| $$  | $$  \  $$$/ | $$  | $$ \____  $$
 /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$   \  $/  |  $$$$$$/ /$$$$$$$/
|_______/  \_______/ \_______/|__/  |__/    \_/    \______/ |_______/ ''')
args = parser.parse_args()
target = dict()
if args.show_inventory_script:
    bash_script_oneliner = functions_linux_inventory.get_bash_script_oneliner(
        functions_linux_inventory.linux_audit_bash_script)
    print(bash_script_oneliner)
elif args.assessment_type:
    print("Getting assessment target...")
    if args.assessment_type == "remote_ssh":
        target = {
            "assessment_type": "remote_ssh",
            "host": args.host,
            "user_name": args.user_name,
        }
        if args.key_path:
            target["key_path"] = args.key_path
        if args.password:
            target["password"] = args.password
    elif args.assessment_type == "localhost":
        target = {
            "assessment_type": "localhost",
            "host": "localhost"
        }
    elif args.assessment_type == "docker_image":
        target = {
            "assessment_type": "docker_image",
            "docker_image": args.docker_image
        }
    elif args.assessment_type == "inventory_file":
        target = {
            "assessment_type": "inventory_file",
            "inventory_file": args.inventory_file_path
        }
    for key in target:
        print("  " + key + ": " + target[key])
    print("Getting OS inventory data...")
    text_block = get_text_block(target)
    os_data = get_os_data_dict(text_block)
    print("  os_name: " + os_data["os_name"])
    print("  os_version: " + os_data["os_version"])
    print("  package_list_len: " + str(len(os_data["package_list"])))
    print("Getting vulnerability data...")
    vulners_linux_audit_data = functions_vuln_detects.get_vulners_linux_audit_data(os_data)
    print("Getting vulnerability report...")
    vulnerability_report = functions_reports.get_vulnerability_report(target, os_data, vulners_linux_audit_data)
    print("-------------")
    print(vulnerability_report['report_text'])

    if args.save_os_data_text_block_path:
        f = open(args.save_os_data_text_block_path, "w")
        f.write(text_block)
        f.close()

    if args.save_os_data_json_path:
        f = open(args.save_os_data_json_path, "w")
        f.write(json.dumps(os_data, indent=4))
        f.close()

    if args.save_vuln_raw_json_path:
        f = open(args.save_vuln_raw_json_path, "w")
        f.write(json.dumps(vulners_linux_audit_data, indent=4))
        f.close()

    if args.save_vuln_report_json_path:
        f = open(args.save_vuln_report_json_path, "w")
        f.write(json.dumps(vulnerability_report['report_dict'], indent=4))
        f.close()




