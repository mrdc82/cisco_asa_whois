import requests
import os
import re

with open('acl_mpls.txt', 'r') as mpls:
    m = mpls.readlines()

    for i in m:
        x = re.match('^172.20.?', i)
        #url = "https://rdap.arin.net/registry/ip/{}".format(i)
        url = "https://rdap.afrinic.net/rdap/ip/{}".format(i)

        response = requests.request("GET", url)

        if i != x:
            with open('mplsresults.txt', 'a') as newfile:
                newfile.writelines(response.text)    