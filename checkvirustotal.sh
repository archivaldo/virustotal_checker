#!/bin/bash
#
# VirusTotal API public key limits:
# 4 requests/minute
# 5760 requests/day
# 178560 requests/month
#

for file in /x64/*.dll
do
  /root/.pyenv/shims/python /root/checkvirustotal.py -f "$file" -c -n
  sleep 45
done

for file in /x86/*.dll
do
  /root/.pyenv/shims/python /root/checkvirustotal.py -f "$file" -c -n
  sleep 45
done
