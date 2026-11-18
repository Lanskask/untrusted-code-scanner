# Throwaway ssh server used only by tests/test_e2e_ssh.py to exercise --host without any cloud account.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt-get update -qq && apt-get install -y -qq openssh-server python3-venv >/dev/null && mkdir -p /run/sshd
CMD ["sh", "-c", "mkdir -p /root/.ssh && echo \"$AUTH_KEY\" > /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && exec /usr/sbin/sshd -D -e"]
