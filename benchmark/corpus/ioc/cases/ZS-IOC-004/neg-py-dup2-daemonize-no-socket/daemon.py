import os


def daemonize(log):
    fd = os.open(log, os.O_WRONLY | os.O_CREAT)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    subprocess.call(['/bin/sh', '-c', 'true'])
