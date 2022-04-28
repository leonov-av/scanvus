import pexpect
import docker
import re

# # I don't use containers.run anymore because it's hard to run complex bash scripts with it
# def execute_command(docker_name, command):
#     client = docker.from_env()
#     output = client.containers.run(docker_name, command)
#     return output.decode('utf-8')

def execute_command_docker_expect(docker_name, command):
    docker_run = pexpect.spawn('docker run --rm -it --entrypoint bash ' + docker_name)
    docker_run.expect('# ', timeout=500)
    docker_run.sendline(command)
    docker_run.expect('# ', timeout=500)
    return(docker_run.before.decode('utf-8'))


def get_docker_execution(client, docker_name, command):
    output = client.containers.run(docker_name, command, entrypoint="")
    return output.decode('utf-8')


def get_version_id_from_os_release(os_release):
    for line in os_release.split("\n"):
        if "=" in line:
            if line.split("=")[0] == "VERSION_ID":
                version = re.sub('"', "", line.split("=")[1])
    return version


def get_package_list_debian(dpkg_query_output):
    # dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\n'|awk '($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}'
    package_list = list()
    for line in dpkg_query_output.split("\n"):
        if re.findall("^install ok ",line):
            components = line.split(" ")
            package_list.append(components[3] + " " + components[4] + " " + components[5])
    return package_list


def get_linux_audit(docker_name):
    # docker_name = '''python:3.9.7-slim'''
    # docker_name = '''centos:7'''
    # docker_name = '''alpine:3.15.1'''
    client = docker.from_env()
    hostname = re.sub("\n","",get_docker_execution(client, docker_name, command='hostname'))
    os_release = get_docker_execution(client, docker_name, command="cat /etc/os-release")
    linux_kernel = get_docker_execution(client, docker_name, command="uname -r")

    is_ubuntu = False
    is_debian = False
    is_centos = False
    is_redhat = False
    is_alpine = False

    if "ubuntu" in os_release:
        is_ubuntu = True
    elif "debian" in os_release:
        is_debian = True
    elif "centos" in os_release:
        is_centos = True
    elif "redhat" in os_release:
        is_redhat = True
    elif "alpine" in os_release:
        is_alpine = True

    if is_ubuntu:
        os_name = "ubuntu"
        os_version = get_version_id_from_os_release(os_release)
        command = '''dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\n' '''
        dpkg_query_output = re.sub("\n$","",get_docker_execution(client, docker_name, command))
        package_list_debian = get_package_list_debian(dpkg_query_output)
        packages = "\n".join(package_list_debian)
    elif is_debian:
        os_name = "debian"
        os_version = get_version_id_from_os_release(os_release)
        command = '''dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\n' '''
        dpkg_query_output = re.sub("\n$","",get_docker_execution(client, docker_name, command))
        package_list_debian = get_package_list_debian(dpkg_query_output)
        packages = "\n".join(package_list_debian)
    elif is_centos:
        os_name = "centos"
        os_version = get_version_id_from_os_release(os_release)
        command = '''rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' '''
        packages = re.sub("\n$","",get_docker_execution(client, docker_name, command))
    elif is_redhat:
        os_name = "redhat"
        os_version = get_version_id_from_os_release(os_release)
        command = '''rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' '''
        packages = re.sub("\n$","",get_docker_execution(client, docker_name, command))
    elif is_alpine:
        os_name = "alpine"
        os_version = get_version_id_from_os_release(os_release)
        command = '''apk list --installed'''
        packages = re.sub("\n$","",get_docker_execution(client, docker_name, command))

    output = "========= BEGIN =========" + "\n"
    output += "hostname:" + hostname + "\n"
    output += "os_name:" + os_name + "\n"
    output += "os_version:" + os_version + "\n"
    output += "linux_kernel:" + linux_kernel + "\n"
    output += "========= packages =========" + "\n"
    output += packages + "\n"
    output += "=========  END  =========" + "\n"

    return output