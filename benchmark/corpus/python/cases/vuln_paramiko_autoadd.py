# ZS-PY-052: AutoAddPolicy silently trusts any SSH host key
import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
