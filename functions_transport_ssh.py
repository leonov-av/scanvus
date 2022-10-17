import paramiko


def get_ssh_client(target):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy)
    if 'password' in target:
        client.connect(hostname=target['host'],
                       username=target['user_name'],
                     #  key_filename=target['key_path'],
                       password=target['password'])
    else:
        client.connect(hostname=target['host'],
                       username=target['user_name'],
                       key_filename=target['key_path'])
    return client


def close_ssh_client(ssh_client):
    ssh_client.close()


def execute_command(ssh_client, command):
    stdin, stdout, stderr = ssh_client.exec_command(command)
    return {"output": str(stdout.read(), 'utf-8'),
            "errors": str(stderr.read(), 'utf-8')}
