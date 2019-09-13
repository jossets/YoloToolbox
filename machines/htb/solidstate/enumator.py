#!/bin/python
#
import sys, os, time
import Queue, thread, subprocess


#
# Usage
#
def banner():
    print "\n======================"
    print " Autoscan v0.1.0"
    print ""

def usage():
    print "Usage : "+sys.argv[0]+" IP_TARGET [options]"
    exit(1)

if (len(sys.argv)<=1):
    usage()


IPTARGET=sys.argv[1]

OUTDIR='enum'

#
# Asynchronous tasks
#
results= Queue.Queue()
process_count= 0


def on_process_finished(popen, title="XXX"):
    print("Task "+title+" Finished")
    


def process_waiter(popen, description, que, on_process_finished=on_process_finished):
    try: 
        #popen.wait()
        while popen.poll() is None:
            time.sleep(0.5)
            print "."
            if (popen.stdout):
                output = popen.stdout.readline
                if (output):
                    for line in iter(output,''):
                        print "- "+line.rstrip()

    finally: 
        que.put( (description, popen.returncode))
        on_process_finished(popen, description)


def add_process(cmd, title, doWhenFinished=on_process_finished):
    global process_count
    global results
    #proc1= subprocess.Popen("/bin/bash -c "+cmd, stdout=subprocess.PIPE)
    proc1= subprocess.Popen([ cmd ] , shell=True,  stdout=subprocess.PIPE,  stdin=None)
    thread.start_new_thread(process_waiter,
        (proc1, title+" finished", results, doWhenFinished))
    process_count+= 1
    print "["+str(process_count)+"] Starting task : "+title+""

#
#
#
banner()

if (not os.path.isdir(OUTDIR)):
    os.mkdir(OUTDIR)

add_process("nmap "+IPTARGET+" -o "+OUTDIR+"/nmap_"+IPTARGET+".txt", "NMap simple")
add_process("nmap -sC -sV -A "+IPTARGET+" -o "+OUTDIR+"/nmap_"+IPTARGET+"_recon.txt", "NMap recon")
#add_process("nmap -sV -p- "+IPTARGET+" -o "+OUTDIR+"/nmap_"+IPTARGET+"_all_tcp.txt", "NMap all TCP")



while process_count > 0:
    description, rc= results.get()    
    process_count-= 1
    print "remaining tasks : ", process_count

#
# Restore stdin/stdout
sys.stdout = sys.__stdout__
sys.stderr = sys.__stderr__

print "En cas de pb: stty echo"


