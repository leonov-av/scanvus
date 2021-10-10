import docker


def execute_command(docker_name, command):
    client = docker.from_env()
    output = client.containers.run(docker_name, command)
    return output.decode('utf-8')
