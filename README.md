# VirusTotal auto checker.
This python script check if a file hash exists on Virustotal and notify the sysadmin via email. (thinked to be run in a crontab.)

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
Edit checkvirustotal.py and add your virustotal API key and email.
```

```
$ ./checkvirustotal.py -f ~/Desktop/myfiles/unknown.pdf
$ ./checkvirustotal.py -f ~/Desktop/myfiles/unknown.pdf -c -n
```