vulnsio_linux_audit_bash_script = '''
hostname=`hostname`; 
linux_kernel=`uname -r`; 
is_ubuntu=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Ubuntu\\|ubuntu"`; 
is_debian=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Debian\\|debian"`; 
is_centos=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "CentOS\\|centos"`;
is_redhat=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Red Hat\\|redhat\\|rhel"`;
is_alpine=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Alpine Linux\\|alpine"`;
is_oracle=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Oracle Linux"`;
is_virtuozzo=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Virtuozzo\\|virtuozzo"`;
is_amazon=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Amazon Linux\\|amazon\\|amzn"`;
is_rocky=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "Rocky Linux\\|rocky"`;
is_redos=`cat /etc/os-release | grep "NAME=\\|ID=" | grep "RED OS\\|redos"`;
if [ "$is_ubuntu" != ""  ]; 
then 
    os_name="ubuntu"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture} ${Source}\\n' | 
              awk '($1 == "install") && ($2 == "ok") {print $4":::"$5":::"$6":::"$7" "$8}'`; 
elif [ "$is_debian" != ""  ]; 
then 
    os_name="debian"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`dpkg-query -W -f='${Status} ${Package} ${Version} ${Architecture} ${Source}\\n' | 
              awk '($1 == "install") && ($2 == "ok") {print $4":::"$5":::"$6":::"$7" "$8}'`; 
elif [ "$is_oracle" != ""  ]; 
then 
    os_name="oracle"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    if [[ $os_version =~ ^8 ]]; then
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|:::%|MODULARITYLABEL?{%{MODULARITYLABEL}}:{}|\\n'`;
    else
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|\\n'`;  
    fi; 
elif [ "$is_centos" != ""  ]; 
then 
    os_name="centos"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    if [[ $os_version =~ ^8 ]]; then
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|:::%|MODULARITYLABEL?{%{MODULARITYLABEL}}:{}|\\n'`;
    else
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|\\n'`;  
    fi; 
elif [ "$is_redhat" != ""  ]; 
then 
    os_name="redhat"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    if [[ $os_version =~ ^8 ]]; then
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|:::%|MODULARITYLABEL?{%{MODULARITYLABEL}}:{}|\\n'`;
    else
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|\\n'`;  
    fi;  
elif [ "$is_virtuozzo" != ""  ]; 
then 
    os_name="virtuozzo"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    if [[ $os_version =~ ^8 ]]; then
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|:::%|MODULARITYLABEL?{%{MODULARITYLABEL}}:{}|\\n'`;
    else
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|\\n'`;  
    fi;  
elif [ "$is_rocky" != ""  ]; 
then 
    os_name="rocky"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    if [[ $os_version =~ ^8 ]]; then
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|:::%|MODULARITYLABEL?{%{MODULARITYLABEL}}:{}|\\n'`;
    else
        packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|\\n'`;  
    fi;  
elif [ "$is_amazon" != ""  ]; 
then 
    os_name="amazon"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|\\n'`;  
elif [ "$is_redos" != ""  ]; 
then 
    os_name="redos"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"\\"" '{printf $2}'`; 
    packages=`rpm -qa --qf '%{NAME}:::%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}:::%|ARCH?{%{ARCH}}:{noarch}|:::%|SOURCERPM?{%{SOURCERPM}}:{}|\\n'`;  
elif  [ "is_alpine" != ""  ]; 
then 
    os_name="alpine"; 
    os_version=`cat /etc/os-release | grep "VERSION_ID=" | awk -F"=" '{printf $2}'`; 
    packages=`apk list --installed | sed -r 's/(.+)-([^-]+-r[^-]+) (\\S+) \\{(\\S+)\\}.*/\\1:::\\2:::\\3:::\\4/'`; 
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