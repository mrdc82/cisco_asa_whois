#!/bin/sh

for ip in $(cat acl_mpls_new.txt);
do whois $ip | echo "$ip \n$(grep 'org-name\|address\|org\|country\|person')\n";
done > whois_mpls.txt