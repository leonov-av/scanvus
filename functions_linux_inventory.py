import re

bash_script = '''
hostname=`hostname`; 
is_ubuntu=`cat /etc/os-release | grep "ubuntu"`; 
is_debian=`cat /etc/os-release | grep "debian"`; 
is_centos=`cat /etc/os-release | grep "centos"`;
if [ "$is_ubuntu" != ""  ]; 
then 
    os_name="ubuntu"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\\n' | 
              awk '($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}'`; 
fi; 
if [ "$is_debian" != ""  ]; 
then 
    os_name="debian"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\\n' | 
              awk '($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}'`; 
fi; 
if [ "$is_centos" != ""  ]; 
then 
    os_name="centos"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'`; 
fi; 
echo "========= BEGIN ========="; 
echo "hostname:$hostname"; 
echo "os_name:$os_name"; 
echo "os_version:$os_version";
echo "=== packages ==="; 
echo "$packages";  
echo "=========  END  =========";
'''

def get_bash_script_oneliner(bash_script):
    oneliner = ""
    for line in bash_script.split("\n"):
        line = re.sub("^ *", "", line)
        line = re.sub(" *$", "", line)
        oneliner += line + " "
    return oneliner

def get_hostname_from_text_block(block):
    hostname = ""
    for line in block.split("\n"):
        if "hostname:" in line:
            hostname = line.split(":")[1]
    return hostname

def get_os_name_from_text_block(block):
    os_name = ""
    for line in block.split("\n"):
        if "os_name:" in line:
            os_name = line.split(":")[1]
    return os_name

def get_os_version_from_text_block(block):
    os_version = ""
    for line in block.split("\n"):
        if "os_version:" in line:
            os_version = line.split(":")[1]
    return os_version

def get_os_packages_from_text_block(block):
    os_packages = list()
    in_block = False
    for line in block.split("\n"):
        if "==" in line:
            in_block = False
        if in_block:
            os_packages.append(line)
        if "=== packages ===" in line:
            in_block = True
    return os_packages