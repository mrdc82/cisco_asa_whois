import re
import glob, os
import subprocess
import tkinter as tk
from tkinter import filedialog

root = tk.Tk()
root.withdraw()

file_path = filedialog.askopenfilename()
print('File loaded')

#touch file to avoid file not found error when running first time
list_of_files = ['acl_in.txt','acl_out.txt','acl_mpls.txt','acl_in_new.txt','acl_out_new.txt','acl_mpls_new.txt','whois_inside.txt','whois_outside.txt','whois_mpls.txt',
                'new_acl_in.txt','new_acl_out.txt','new_acl_mpls.txt']

for file in list_of_files:
    if file in os.listdir():
        print('found ' + file)
    else:
        open(file, 'a').close()
        print('creating ' + file)

os.remove('acl_in.txt')
os.remove('acl_out.txt')
os.remove('acl_mpls.txt')
os.remove('acl_in_new.txt')
os.remove('acl_out_new.txt')
os.remove('acl_mpls_new.txt')
os.remove('whois_inside.txt')
os.remove('whois_outside.txt')
os.remove('whois_mpls.txt')
os.remove('new_acl_in.txt')
os.remove('new_acl_out.txt')
os.remove('new_acl_mpls.txt')

def strip(inside, outside, mpls):

    acl_in = []
    acl_out = []
    acl_mpls = []
    acl_in_new = []


    m = '255.255.'
    o = 'object'

    mcount = 0
    icount = 0
    ocount = 0


#read the asa config file and strip out the lines to the relevant lists
    with open(file_path, 'r') as file:
        for i in file:
            if inside in i and m not in i and o not in i:
                acl_in.append(i.split())
            elif outside in i and m not in i and o not in i:
                acl_out.append(i.split())
            elif mpls in i and m not in i and o not in i:
                acl_mpls.append(i.split())
            else:
                continue

#formatting ip for acl inside
    for i in acl_in:
        if len(i) > 8:
            x = i[8]
            aa=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",x)
            if aa:
                with open('acl_in.txt', 'a') as file:
                    file.write(x + '\n')
            else:
                continue



#formatting ip for acl outside
    for i in acl_out:
        if len(i) > 8:
            x = i[6]
            aa=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",x)
            if aa:
                ocount += 1
                with open('acl_out.txt', 'a') as file:
                    file.write(x + '\n')
            else:
                continue

#formatting ip for acl mpls
    for i in acl_mpls:
        if len(i) > 8:
            x = i[6]
            aa=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",x)
            if aa:
                mcount += 1
                with open('acl_mpls.txt', 'a') as file:
                    file.write(x + '\n')
            else:
                continue

#tcp search
strip("access-list inside extended permit tcp host", "access-list outside extended permit tcp host", "access-list mpls extended permit tcp host")
#udp search
strip("access-list inside extended permit udp host", "access-list outside extended permit udp host", "access-list mpls extended permit udp host")
#icmp search
strip("access-list inside extended permit icmp host", "access-list outside extended permit icmp host", "access-list mpls extended permit icmp host")

#remove private addresses inside
with open('acl_in.txt', 'r') as file:
    j = file.readlines()
    with open('new_acl_in.txt', 'a') as newfile:
        for i in j:
            if i.startswith('10.') or i.startswith('172.16.') or i.startswith('172.31.') or i.startswith('192.168'):
                continue
            else:
                newfile.writelines(i)

#remove private addresses outside
with open('acl_out.txt', 'r') as file:
    j = file.readlines()
    with open('new_acl_out.txt', 'a') as newfile:
        for i in j:
            if i.startswith('10.') or i.startswith('172.16.') or i.startswith('172.31.') or i.startswith('192.168'):
                continue
            else:
                newfile.writelines(i)

#remove private addresses mpls
with open('acl_mpls.txt', 'r') as file:
    j = file.readlines()
    with open('new_acl_mpls.txt', 'a') as newfile:
        for i in j:
            if i.startswith('10.') or i.startswith('172.16.') or i.startswith('172.31.') or i.startswith('192.168'):
                continue
            else:
                newfile.writelines(i)

sortin = 'sort new_acl_in.txt | uniq > acl_in_new.txt'
sortout = 'sort new_acl_out.txt | uniq > acl_out_new.txt'
sortmpls = 'sort new_acl_mpls.txt | uniq > acl_mpls_new.txt'

os.system(sortin)
os.system(sortout)
os.system(sortmpls)

#count number of ip's being checked
tot_in = 0
tot_out = 0
tot_mpls = 0

with open('acl_in_new.txt', 'r') as file:
    for i in file:
        tot_in += 1

with open('acl_out_new.txt', 'r') as file:
    for i in file:
        tot_out += 1

with open('acl_mpls_new.txt', 'r') as file:
    for i in file:
        tot_mpls += 1

print('Total Inside destination addresses to check: ', tot_in)
print('Total Outside source addresses to check: ', tot_out)
print('Total mpls source addresses to check: ', tot_mpls)

#print(os.listdir())
subprocess.run('whois_inside.sh')
print('whois inside addresses complete')
subprocess.run('whois_outside.sh')
print('whois outside addresses complete')
subprocess.run('whois_mpls.sh')
print('whois mpls addresses complete')