#!/usr/bin/python

import virustotal, argparse, os, sys, hashlib, smtplib

from email.mime.text import MIMEText
from smtplib import SMTP

VIRUSTOTALKEY = ''
EMAIL = ''

#-------------------------------------------------------------------------------------------
# Variables
#-------------------------------------------------------------------------------------------
buffer = 65536
localfile = None
check = False
notify = False
md5 = hashlib.md5()
sha1 = hashlib.sha1()
sha256 = hashlib.sha256()
sha512 = hashlib.sha512()
v = virustotal.VirusTotal(VIRUSTOTALKEY)


def checkFile():
    try:
        if os.path.isfile(localfile) is False:
           print bcolors.WARNING,'[?] Does: ' + file + ' Exist?',bcolors.ENDC
           print bcolors.FAIL,'[!] Error: File not found...\n',bcolors.ENDC
           exit(0)
        print bcolors.OKBLUE,('[+] Checking File:   ' + localfile + '\n'),bcolors.ENDC   
        with open(localfile, 'rb') as f:
                while True:
                    data = f.read(buffer)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)
                    sha512.update(data)
        print bcolors.BOLD,'[+] Hash Results:\n',bcolors.ENDC
        print bcolors.OKGREEN,(' MD5:    {0}'.format(md5.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA1:   {0}'.format(sha1.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA256: {0}'.format(sha256.hexdigest())),bcolors.ENDC
        print bcolors.OKGREEN,(' SHA512: {0}'.format(sha512.hexdigest())) + '\n',bcolors.ENDC
        
        
        #checking virustotal...
        if check is True:        
                   if VIRUSTOTALKEY is '':
                       print bcolors.FAIL,'[!] Error: You did not specify your Virus Total API Key in the source.',bcolors.ENDC
                       print bcolors.FAIL,'[!] Exiting.\n',bcolors.ENDC
                       exit (0)
        
        
                   localsha = sha256.hexdigest()
                   report = v.get(localsha)
                   if report is None:
                       print bcolors.FAIL,'\n[!] Failed: SHA256 Hash does not exist on Virustotal!\n',bcolors.ENDC
                       exit(0)
                   else:
                       pass
        
                   if report.done:
                       print bcolors.BOLD,'[+] Virustotal Report:',bcolors.ENDC
                       print bcolors.OKBLUE,'[+] - Link:',report.permalink,'\n',bcolors.ENDC
                       print bcolors.BOLD,' [+] Results:\n',bcolors.ENDC
                       print bcolors.OKGREEN,' [+] Resource Status:',report.status,bcolors.ENDC
                       print bcolors.OKGREEN,' [+] Antivirus Total:',report.total,bcolors.ENDC
                       print bcolors.OKGREEN,' [+] Antivirus Positives:',report.positives,'\n',bcolors.ENDC
            
                   if notify is True and report.positives > 0:    
                       #we sent the email
                       text = 'Hello master, we have some news: \n\n File: %s \n Report: %s \n Result: %s/%s\n\n' % (localfile, report.permalink, report.total, report.positives)
                       from_address = "totalbot@localhost.com"
                       to_address = EMAIL
                       
                       mime_message = MIMEText(text, "plain")
                       mime_message["From"] = from_address
                       mime_message["To"] = to_address
                       mime_message["Subject"] = "We have some problems. Totalbot."
    
                       smtp = SMTP("localhost")
                       smtp.sendmail(from_address, to_address, mime_message.as_string())
                       smtp.quit()
                       print bcolors.OKGREEN,('Email sent to {0}'.format(EMAIL)),bcolors.ENDC
           
    except Exception as e:
        print bcolors.FAIL,'[!] Exception: Unable to computate hashes...',e,bcolors.ENDC


def main():
    print bcolors.OKGREEN,'######################################################',bcolors.ENDC
    print bcolors.OKGREEN,'VirusTotal checker V1.0',bcolors.ENDC
    print bcolors.OKGREEN,'######################################################',bcolors.ENDC

#-------------------------------------------------------------------------------------------
# Start:
#-------------------------------------------------------------------------------------------

if __name__ == "__main__":

    class bcolors:
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    main()

#-------------------------------------------------------------------------------------------
# Argument Function:
#-------------------------------------------------------------------------------------------

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Specify a file name, and get its hash.', required=False)
    parser.add_argument('-c', '--check', help='Check to see if hash exists on VirusTotal.', required=False, action='store_true')
    parser.add_argument('-n', '--notify', help='Notify our sysadmin if the result is true.', required=False, action='store_true')
    args = parser.parse_args()
    localfile = args.file
    check = args.check
    notify = args.notify

    
    if localfile is None:
        print bcolors.WARNING,'\n[?] Warning: Nothing to hash. -f (--file).',bcolors.ENDC
        print bcolors.OKGREEN,'[+] Example: ./cobaltbrew -f ~/Downloads/s3cr3t.pdf -c',bcolors.ENDC
        print bcolors.FAIL,'[!] Error: Nothing submitted...\n',bcolors.ENDC
        exit(0)

    checkFile()