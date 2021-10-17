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
    if target["assement_type"] == "remote_ssh":
        ssh_client = functions_transport_ssh.get_ssh_client(target)
        command_result = functions_transport_ssh.execute_command(ssh_client, command=bash_script_oneliner)
        functions_transport_ssh.close_ssh_client(ssh_client)
        if command_result['errors'] != "":
            print("Error: SSH command " + command_result['errors'])
            exit()
        else:
            temp_text_block = command_result['output']
    elif target["assement_type"] == "localhost":
        temp_text_block = functions_transport_localhost.execute_command(command=bash_script_oneliner)
    elif target["assement_type"] == "docker_image":
        temp_text_block = functions_transport_docker.execute_command(docker_name=target["docker_image"],
                                                                command=bash_script_oneliner)
    temp_text_block = functions_linux_inventory.clear_text_block(temp_text_block)
    return temp_text_block


def get_os_data_dict(text_block):
    os_data = dict()
    os_data["os_name"] = functions_linux_inventory.get_os_name_from_text_block(text_block)
    os_data["os_version"] = functions_linux_inventory.get_os_version_from_text_block(text_block)
    os_data['package_list'] = functions_linux_inventory.get_os_packages_from_text_block(text_block)
    # os_data['package_list'] = ["apt 1.0.6 amd64","apt-config-icons 0.12.10-2 all"] # DEBUG
    return os_data


parser = argparse.ArgumentParser(description='Scanvus is a Simple Credentialed Authenticated Network VUlnerability Scanner for Linux systems and docker images')
parser.add_argument('--assement-type', help='Assement type (E.g.: remote_ssh, localhost, docker_image)')
parser.add_argument('--host', help='Remote host to scan (ip of hostname)')
parser.add_argument('--user-name', help='Username to authenticate on remote host')
parser.add_argument('--key-path', help='Path to the private key file to authenticate on remote host')
parser.add_argument('--docker-image', help='Docker image')
parser.add_argument('--save-os-data-text-block-path', help='Path to the OS data Text Block result file')
parser.add_argument('--save-os-data-json-path', help='Path to the OS data JSON result file')
parser.add_argument('--save-vuln-raw-json-path', help='Path to the Raw Vulnerability data JSON result file')
parser.add_argument('--save-vuln-report-json-path', help='Path to the Vulnerability Report data JSON result file')

args = parser.parse_args()
target = dict()
if args.assement_type:
    if args.assement_type == "remote_ssh":
        target = {
            "assement_type": "remote_ssh",
            "host": args.host,
            "user_name": args.user_name
        }
        if args.key_path:
            target["key_path"] = args.key_path
    elif args.assement_type == "localhost":
        target = {
            "assement_type": "localhost",
            "host": "localhost"
        }
    elif args.assement_type == "docker_image":
        target = {
            "assement_type": "docker_image",
            "docker_image": args.docker_image
        }

    text_block = get_text_block(target)
    os_data = get_os_data_dict(text_block)
    vulners_linux_audit_data = functions_vuln_detects.get_vulners_linux_audit_data(os_data)
    vulnerability_report = functions_reports.get_vulnerability_report(target, os_data, vulners_linux_audit_data)
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




