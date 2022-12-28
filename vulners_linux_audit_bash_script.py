vulners_linux_audit_bash_script = '''
hostname=`hostname`; 
linux_kernel=`uname -r`; 
is_ubuntu=`cat /etc/os-release | grep "ubuntu"`; 
is_debian=`cat /etc/os-release | grep "debian"`; 
is_centos=`cat /etc/os-release | grep "centos"`;
is_redhat=`cat /etc/os-release | grep "redhat"`;
is_fedora=`cat /etc/os-release | grep "fedora"`;
is_alpine=`cat /etc/os-release | grep "alpine"`;
is_oraclelinux=`cat /etc/os-release | grep "Oracle Linux"`;
if [ "$is_ubuntu" != ""  ]; 
then 
    os_name="ubuntu"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\\n' | 
              awk '($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}'`; 
elif [ "$is_debian" != ""  ]; 
then 
    os_name="debian"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture}\\n' | 
              awk '($1 == "install") && ($2 == "ok") {print $4" "$5" "$6}'`;
elif [ "$is_oraclelinux" != ""  ]; 
then 
    os_name="oraclelinux"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'`;  
elif [ "$is_centos" != ""  ]; 
then 
    os_name="centos"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'`; 
elif [ "$is_redhat" != ""  ]; 
then 
    os_name="redhat"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'`;
elif [ "$is_fedora" != ""  ]; 
then 
    os_name="fedora"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n'`;
elif  [ "is_alpine" != ""  ]; 
then 
    os_name="alpine"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`apk list --installed`; 
else
    os_name="unknown"; 
    os_version=""; 
    packages=""; 
fi; 
echo "========= BEGIN ========="; 
echo "hostname:$hostname"; 
echo "linux_kernel:$linux_kernel"; 
echo "os_name:$os_name"; 
echo "os_version:$os_version";
echo "=== packages ==="; 
echo "$packages";  
echo "=========  END  =========";
'''