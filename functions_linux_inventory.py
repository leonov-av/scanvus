import re


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


def get_linux_kernel_from_text_block(block):
    linux_kernel = ""
    for line in block.split("\n"):
        if "linux_kernel:" in line:
            linux_kernel = line.split(":")[1]
    return linux_kernel


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
            if ":::" in line:
                # for Vulns.io API
                os_packages.append([x.strip() for x in line.split(":::")])
            else:
                # for Vulners API
                os_packages.append(line)
        if "=== packages ===" in line:
            in_block = True
    return os_packages


def filter_nonprintable(text):
    import itertools
    # Use characters of control category
    nonprintable = itertools.chain(range(0x00,0x20),range(0x7f,0xa0))
    # Use translate to remove all non-printable characters
    return text.translate({character:None for character in nonprintable})


def clear_text_block(temp_text_block):
    temp_text_block = re.sub("\n", "<new_line>",  temp_text_block)
    temp_text_block = filter_nonprintable(temp_text_block)
    temp_text_block = re.sub("^.*========= BEGIN =========","========= BEGIN =========", temp_text_block)
    temp_text_block = re.sub("=========  END  =========.*","=========  END  =========", temp_text_block)
    temp_text_block = re.sub("<new_line>", "\n",  temp_text_block)
    return temp_text_block


