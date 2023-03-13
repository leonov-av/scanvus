**Scanvus** is a **S**imple **C**redentialed **A**uthenticated **N**etwork **VU**lnerability **S**canner for Linux hosts and Docker images, which uses external vulnerability detections APIs ([Vulners Linux API](https://vulners.com/docs/API_wrapper/linux_audit/) or [Vulns.io API](https://vulns.io/)) under the hood.

![scanvus logo](https://raw.githubusercontent.com/leonov-av/scanvus/main/logo/scanvus_line.png)

## What's ready right now?

You can run a scan for the following targets:
* localhost
```buildoutcfg
python3 scanvus.py --assessment-type "localhost"
```
* remote hosts via SSH (key authentication)
```buildoutcfg
python3 scanvus.py --assessment-type "remote_ssh"  --host "linuxserver1.corporation.com" --user-name "jsmith" --key-path "/home/jsmith/.ssh/id_rsa"
```
* remote hosts via SSH (password authentication)
```buildoutcfg
python3 scanvus.py --assessment-type "remote_ssh"  --host "linuxserver1.corporation.com" --user-name "jsmith" --password "Password123"
```
* docker images 
```buildoutcfg
python3 scanvus.py --assessment-type "docker_image" --docker-image "python:3.9.6-slim-bullseye" 
```
* inventory file 
```buildoutcfg
python3 scanvus.py --show-inventory-script
# Execute bash oneliner on a target host and save output to invent.txt
python3 scanvus.py --assessment-type inventory_file --inventory-file-path  invent.txt
```
### Example of output
```buildoutcfg
$ python3 scanvus.py --assessment-type "docker_image" --docker-image "python:3.9.6-slim-bullseye" 
  /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$    /$$/$$   /$$  /$$$$$$$
 /$$_____/ /$$_____/ |____  $$| $$__  $$|  $$  /$$/ $$  | $$ /$$_____/
|  $$$$$$ | $$        /$$$$$$$| $$  \ $$ \  $$/$$/| $$  | $$|  $$$$$$ 
 \____  $$| $$       /$$__  $$| $$  | $$  \  $$$/ | $$  | $$ \____  $$
 /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$   \  $/  |  $$$$$$/ /$$$$$$$/
|_______/  \_______/ \_______/|__/  |__/    \_/    \______/ |_______/ 
Getting assessment target...
  assessment_type: docker_image
  docker_image: python:3.9.6-slim-bullseye
Getting OS inventory data...
  os_name: debian
  os_version: 11
  package_list_len: 105
Getting vulnerability data...
Getting vulnerability report...
-------------
Vulnerability Report for python:3.9.6-slim-bullseye (docker_image, debian 11, 105 packages)
5 vulnerabilities with levels ['High', 'Medium'] were found
+---+--------+-------------------------+----------------+----------------------------------------------------+
| N | Level  |        Bulletin         |      CVE       |                       Proof                        |
+---+--------+-------------------------+----------------+----------------------------------------------------+
| 1 |  High  | DEBIAN:DSA-4963-1:90BFC | CVE-2021-3711  |     openssl 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1      |
|   |        |                         | CVE-2021-3712  |    libssl1.1 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1     |
+---+--------+-------------------------+----------------+----------------------------------------------------+
| 2 |  High  | DEBIAN:DSA-4963-1:DA7BC | CVE-2021-3712  |     openssl 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1      |
|   |        |                         | CVE-2021-3711  |    libssl1.1 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1     |
+---+--------+-------------------------+----------------+----------------------------------------------------+
| 3 | Medium | DEBIAN:DLA-2766-1:9EFDC | CVE-2021-3712  |     openssl 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1      |
|   |        |                         |                |    libssl1.1 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1     |
+---+--------+-------------------------+----------------+----------------------------------------------------+
| 4 | Medium | DEBIAN:DLA-2771-1:D1964 | CVE-2018-20217 |   libk5crypto3 1.18.3-6 amd64 < 1.18.3-6+deb11u1   |
|   |        |                         | CVE-2018-5729  | libgssapi-krb5-2 1.18.3-6 amd64 < 1.18.3-6+deb11u1 |
|   |        |                         | CVE-2018-5730  |    libkrb5-3 1.18.3-6 amd64 < 1.18.3-6+deb11u1     |
|   |        |                         | CVE-2021-37750 | libkrb5support0 1.18.3-6 amd64 < 1.18.3-6+deb11u1  |
+---+--------+-------------------------+----------------+----------------------------------------------------+
| 5 | Medium | DEBIAN:DLA-2774-1:D8CE0 | CVE-2021-3712  |     openssl 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1      |
|   |        |                         |                |    libssl1.1 1.1.1k-1 amd64 < 1.1.1k-1+deb11u1     |
+---+--------+-------------------------+----------------+----------------------------------------------------+
```

### Installation 
```ignorelang
pip3 install -r requirements.txt
```

### Options
```buildoutcfg
$ python3 scanvus.py -h
  /$$$$$$$  /$$$$$$$  /$$$$$$  /$$$$$$$  /$$    /$$/$$   /$$  /$$$$$$$
 /$$_____/ /$$_____/ |____  $$| $$__  $$|  $$  /$$/ $$  | $$ /$$_____/
|  $$$$$$ | $$        /$$$$$$$| $$  \ $$ \  $$/$$/| $$  | $$|  $$$$$$ 
 \____  $$| $$       /$$__  $$| $$  | $$  \  $$$/ | $$  | $$ \____  $$
 /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$   \  $/  |  $$$$$$/ /$$$$$$$/
|_______/  \_______/ \_______/|__/  |__/    \_/    \______/ |_______/ 
usage: scanvus.py [-h] [--audit-service {vulners,vulnsio}] [--assessment-type ASSESSMENT_TYPE] [--host HOST] [--user-name USER_NAME] [--key-path KEY_PATH] [--password PASSWORD]
                  [--docker-image DOCKER_IMAGE] [--show-inventory-script] [--inventory-file-path INVENTORY_FILE_PATH] [--save-os-data-text-block-path SAVE_OS_DATA_TEXT_BLOCK_PATH]
                  [--save-os-data-json-path SAVE_OS_DATA_JSON_PATH] [--save-vuln-raw-json-path SAVE_VULN_RAW_JSON_PATH] [--save-vuln-report-json-path SAVE_VULN_REPORT_JSON_PATH]
                  [--save-vuln-report-text-path SAVE_VULN_REPORT_TEXT_PATH]

Scanvus is a Simple Credentialed Authenticated Network VUlnerability Scanner for Linux systems and docker images

options:
  -h, --help            show this help message and exit
  --audit-service {vulners,vulnsio}
                        Audit API service:"vulners" (default) - https://vulners.com, "vulnsio" - https://vulns.io
  --assessment-type ASSESSMENT_TYPE
                        Assessment type (E.g.: remote_ssh, localhost, docker_image, inventory_file)
  --host HOST           Remote host to scan (ip of hostname)
  --user-name USER_NAME
                        Username to authenticate on remote host
  --key-path KEY_PATH   Path to the private key file to authenticate on remote host
  --password PASSWORD   User password or private key passphrase to authenticate on remote host
  --docker-image DOCKER_IMAGE
                        Docker image
  --show-inventory-script
                        Shows inventory bash oneliner
  --inventory-file-path INVENTORY_FILE_PATH
                        Inventory file to process
  --save-os-data-text-block-path SAVE_OS_DATA_TEXT_BLOCK_PATH
                        Path to the OS data Text Block result file
  --save-os-data-json-path SAVE_OS_DATA_JSON_PATH
                        Path to the OS data JSON result file
  --save-vuln-raw-json-path SAVE_VULN_RAW_JSON_PATH
                        Path to the Raw Vulnerability data JSON result file
  --save-vuln-report-json-path SAVE_VULN_REPORT_JSON_PATH
                        Path to the Vulnerability Report data JSON result file
  --save-vuln-report-text-path SAVE_VULN_REPORT_TEXT_PATH
                        Path to the Vulnerability Report data Text result file
```

## Requirements
* Install necessary modules from requirements.txt 
```
pip3.8 install -r requirements.txt
```
* Set the Vulners Linux API key in credentials.py

### Docker image checks
To check docker images you should install docker in your system. See the [manual for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

```
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io
```
Configure groups:
```
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
docker run hello-world
```

Start service:
```
service docker start
sudo chmod 666 /var/run/docker.sock
```

#### Known issues

Scanvus docker_image assessment may not work correctly with some docker images due to pexpect issues. In this case you can try run docker container with `docker run --rm -it --entrypoint bash <image>`, run the inventory script (`scanvus.py --show-inventory-script`) manually, save inventory output to a file and run scanvus against this file (`scanvus.py --assessment-type inventory_file --inventory-file-path invent.txt`).

If the docker image is available as a file, you can run docker container as:

```
docker load -i test-image.tar.gz
docker image ls
    REPOSITORY                                                    TAG            IMAGE ID       CREATED       SIZE
    docker.corporation.com/cicd-images/base-image   test-image   dd452a4e174c   8 weeks ago   536MB
docker run -i -t dd452a4e174c /bin/bash 
```

To remove unused docker images:

```docker image ls | awk '{print $3}' | xargs -i docker image rm -f '{}'```
