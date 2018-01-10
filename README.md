# VirusTotal auto checker.
check if the file hash exists on Virustotal and notify the sysadmin via mail. (thinked to by runned in a crontab.)

# Credits
Inspired by https://github.com/xakepnz/COBALTBREW

<b>[+] Language:</b> Python 2.7<br />
<b>[+] OS:</b> Linux<br />

## Requirements:

[+] <b>OPTIONAL</b> Virustotal API Key - https://www.virustotal.com/<br />
[+] Python dependencies (see below).

## Install:

```
$ git clone https://github.com/archivaldo/virustotal_checker.git
```

```
$ cd 
```

```
$ pip install -r requirements.txt
```

```
$ chmod +x checkvirustotal.py
```

```
$ ./checkvirustotal.py -f ~/Desktop/myfiles/unknown.pdf
$ ./checkvirustotal.py -f ~/Desktop/myfiles/unknown.pdf -c -n
```