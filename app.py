import codecs, re, os, sys
import subprocess
import ctypes
from collections import Counter

import tkinter as tk
from tkinter import filedialog


def isadmin():
    try:
        iadmin = (os.getuid() == 0)
    except AttributeError:
        iadmin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return iadmin


def fileopen():
    root = tk.Tk()
    root.withdraw()
    filepath = filedialog.askopenfilename()
    return filepath


def iplistcsv(filename, ip):
    with codecs.open(filename, 'r', 'utf-8') as f:
        log = f.read()
        ipl = re.findall(ip, log)
    count=Counter(ipl)
    iplist = [ item for item in count if int(count[item]) > 11 ]
    return iplist


def iplistreg(filename):

    ipmask = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    rulename = 'blockIP'
    fromcsv = iplistcsv(filename, ipmask)

    try:
        rulecheck = str(subprocess.check_output(r'netsh advfirewall firewall show rule name="{}"'.format(str(rulename), shell=True)))
        regipl = re.findall(ipmask, rulecheck)
        fulllist = regipl + fromcsv
        list = ''.join( str(ip) + ',' for ip in fulllist)
        os.system(r'netsh advfirewall firewall set rule name="{}" new remoteip="{}"'.format(str(rulename), list))
        ctypes.windll.user32.MessageBoxW(0, 'Done!\nThe Rule \'blockIP\' successfully updated!', 'IPBlocker', 64)

    except subprocess.CalledProcessError:
        list = ''.join( str(ip) + ',' for ip in fromcsv)
        os.system(r'netsh advfirewall firewall add rule name="{}" action=block dir=IN remoteip="{}"'.format(str(rulename), list))
        ctypes.windll.user32.MessageBoxW(0, 'Done!\nThe Rule \'blockIP\' successfully created, ips from log file was added!', 'IPBlocker', 64)


if __name__ == '__main__':

    if isadmin():
        filename = fileopen()
        if os.path.exists(filename):
            iplistreg(filename)
        else:
            print('File not selected. Bye!')
    else:
        ctypes.windll.user32.MessageBoxW(0, 'You should run this application as an Administrator!', 'IPBlocker', 16)
