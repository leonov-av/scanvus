import pexpect

# # I don't use containers.run anymore because it's hard to run complex bash scripts with it
# def execute_command(docker_name, command):
#     client = docker.from_env()
#     output = client.containers.run(docker_name, command)
#     return output.decode('utf-8')

def execute_command(docker_name, command):
    docker_run = pexpect.spawn('docker run --rm -it --entrypoint bash ' + docker_name)
    docker_run.expect('# ', timeout=500)
    docker_run.sendline(command)
    docker_run.expect('# ', timeout=500)
    return(docker_run.before.decode('utf-8'))

