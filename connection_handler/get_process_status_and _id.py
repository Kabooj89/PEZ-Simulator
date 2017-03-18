import re
import time
from utilities.connection_handler.connections import SSH, ConnectionParameters


def search_for_re(reg_ex, data):
    # Input search query and a string to be searched upon, return the process pid if it is running, None otherwise.
    pid = None
    for line in data.splitlines():
        match = re.match(reg_ex, line)
        if match:
            x = line.split(reg_ex)[1].split()
            if x[0] == 'running':
                pid = x[1]
                break
    return pid


def main():
    connection_params = ConnectionParameters()
    my_ssh = SSH(connection_params)
    my_ssh.connect()
    stdin, stdout, stderr = my_ssh.send_cmd('/opt/CSCOcpm/bin/cpmcontrol.sh status')
    time.sleep(5)
    stdout_data = ''.join(stdout)
    pid = search_for_re('Application Server', stdout_data)
    my_ssh.kill_connection()
    print(pid)

if __name__ == '__main__':
    main()

