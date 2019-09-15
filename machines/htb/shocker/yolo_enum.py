#!/bin/python
#
import sys, os, time
import Queue, thread, subprocess, shlex
import curses
import signal


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
IMGDIR='images'
#
# Asynchronous tasks
#
results= Queue.Queue()
process_count= 0


def on_process_finished(popen, title="XXX"):
    if (False):
        print(title+" Finished")
    

TRACE_STDOUT=False

def process_waiter(popen, ip, port, description, que, on_stdout_read=None, on_process_finished=None):
    global procs
    try: 
        #popen.wait()
        while popen.poll() is None:
            time.sleep(0.5)
            if (popen.stdout):
                output = popen.stdout.readline
                if (output):
                    for line in iter(output,''):
                        if (TRACE_STDOUT):
                            print "- "+line.rstrip()
                        if (on_stdout_read):
                            on_stdout_read(ip, port, line)
    except Exception as ex:
        print ("Pb ["+description+"]")
        print (ex)

    finally: 
        que.put( (description, popen.returncode))
        if (on_process_finished ):
            on_process_finished(popen, description)
        procs.remove(popen)


procs = []
def add_process(cmd, title, ip, port, on_stdout_read=None, doWhenFinished=None):
    global process_count
    global results
    #proc1= subprocess.Popen("/bin/bash -c "+cmd, stdout=subprocess.PIPE)
    #proc1= subprocess.Popen(cmd , shell=True,  stdout=subprocess.PIPE,  stdin=None)
    #proc1= subprocess.Popen(cmd , shell=False, stdout=subprocess.PIPE,  stdin=None, stderr=subprocess.PIPE)
    proc1= subprocess.Popen(cmd , shell=False, stdout=subprocess.PIPE,  stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.title = title
    proc1.ip = ip
    thread.start_new_thread(process_waiter, (proc1, ip, port, title, results, on_stdout_read, doWhenFinished))
    procs.append(proc1)
    process_count+= 1
    print "["+str(process_count)+"] Starting task : "+title+""


#
# Port base scan
#
ports=[]
def found_port(ip, port):
    #print(port)
    if (not port in ports):
        ports.append(port)
        print "+ Found new port "+str(port)
        scan_port(ip, port)

#
# Tool
#
def url_to_png(url, pngfile):
    cmd = "wkhtmltoimage "+url+" "+pngfile 
    print ("==> "+cmd)
    #out = os.system(cmd + ">/dev/null")
    #print out
    proc = subprocess.Popen(cmd , shell=True, stdout=subprocess.PIPE,  stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()

def url2print(url):
    url = url.rstrip()
    url = url.replace('/', '_')
    return url


#
# Dirb
#
# ==> DIRECTORY: http://10.10.10.51:80/assets/
# ==> DIRECTORY: http://10.10.10.51:80/images/
# + http://10.10.10.51:80/index.html (CODE:200|SIZE:7776)
# + http://10.10.10.51:80/server-status (CODE:403|SIZE:299)
# ---- Entering directory: http://10.10.10.51:80/assets/ ----
# (!) WARNING: Directory IS LISTABLE. No need to scan it.

#
# Process each Dirb entry found
def on_dirb_stdout_read(ip, port, line):
    #print "Dirb - "+line
    if (line.find('DIRECTORY: ')>0):
        #print "Found dir"
        args = line.split(" ")
        #print args
        if args[2]:
            url = args[2]
            url = url.rstrip()
            print ("DIRB: found dir "+url+" "+str(args))
            pngfile = "images/"+url2print(url)+".png"
            if (not os.path.isfile(pngfile)):
                url_to_png(url, pngfile)

    if (line.find('CODE:')>0):
        #print "Found file"
        args = line.split(" ")
        #print args
        if args[1]:
            url = args[1]
            url = url.rstrip()
            print ("DIRB: found dir "+url+" "+str(args))
            pngfile = "images/"+url2print(url)+".png"
            if (not os.path.isfile(pngfile)):
                url_to_png(url, pngfile)

def on_http_cewl_finished(popen, title="XXX"):
    # tr '[:upper:]' '[:lower:]' <enum/site_words.txt >enum/site_words_lower.txt
    cmd = "tr '[:upper:]' '[:lower:]' <"+os.getcwd()+"/enum/site_words.txt >"+os.getcwd()+"/enum/site_words_lower.txt"
    os.system(cmd)

#
# Gobuster
#
#/index.html (Status: 200) [Size: 7774]
#/images (Status: 301) [Size: 311]
#/about.html (Status: 200) [Size: 7161]
def on_gobuster_stdout_read(ip, port, line):
    #print "Dirb - "+line
    if (line.find('(Status:')>0):
        #print "Found dir"
        args = line.split(" ")
        #print args
        if args[0]:
            path = args[0]
            path = path.rstrip()
            url = "http://"+ip+":"+port+path
            print ("GOBUSTER: found dir "+url+" "+str(args))
            pngfile = "images/"+url2print(url)+".png"
            if (not os.path.isfile(pngfile)):
                url_to_png(url, pngfile)

#
# Run  HTTP scans
#
def scan_http(ip, port):
    print "Scan HTTP "+ip
    url = "http://"+ip+":"+str(port)
    print_url = url2print(url)
    print "scan "+url

    #
    # Index png
    pngfile = "images/"+url2print(url)+".png"
    url_to_png(url, pngfile)

    #
    # Robots.txt
    add_process([ "curl", url+"/robots.txt", "-o", "enum/robots.txt" ], "curl "+url+"/robots.txt", IPTARGET, port)

    #
    # cewl http://192.168.168.168/index.html -m 2 -w cewl.lst
    add_process([ "cewl", url, "-m", "2", "-w", "enum/site_words.txt", "-e", "--email_file", "enum/site_mails.txt" ], "cewl "+url, IPTARGET, port, None, on_http_cewl_finished)

    # dirb http://10.10.10.51:80 -S -o dirb_10.10.10.51:80.txt
    # -S : dont print each tested entry
    # -o output file
    dirb_outfile = "enum/dirb_"+print_url+".txt"
    add_process([ "dirb", url, "-S", "-o", dirb_outfile ], "Dirb "+url, IPTARGET, port, on_dirb_stdout_read)

    # nikto -h  10.10.10.51 -p 80 -oupu
    nikto_outfile = "enum/nikto_"+print_url+".txt"
    add_process([ "nikto", "-h", ip, "-p", port, "-o", nikto_outfile, "-ask","no" ], "Nikto "+url, IPTARGET, port)

    # /opt/gobuster/gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://172.16.27.142  -l -x html,php,js,txt
    gobuster_outfile = "enum/go_buster_"+print_url+".txt"
    add_process([ "/opt/gobuster/gobuster", "dir", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "-u", url, "-l", "-x", "html,php,js,txt,asp,aspx,sh,py", "-o", gobuster_outfile ], "Gobuster "+url, IPTARGET, port, on_gobuster_stdout_read)


def scan_port(ip, port):
    #print "==> scanning "+str(port)
    if (port=="80" or port=="8080"):
        scan_http(ip, port)
    elif (port=="22"):
        print "try ssh"
    else:
        print "Port unkown..."



#
# NMap scan
#

#def on_process_finished(popen, title="XXX"):
#    print(title+" Finished")

def on_nmap_stdout_read(ip, port, line):
    if (line.find('open')>0):
        args = line.split("/")
        if args[0]:
            found_port(ip, args[0])

def run_program():
    global process_count
    global results
    #
    banner()

    # Create output directory
    if (not os.path.isdir(OUTDIR)):
        os.mkdir(OUTDIR)
    if (not os.path.isdir(IMGDIR)):
        os.mkdir(IMGDIR)    

    #
    # NMap scans
    #
    add_process([ "nmap", IPTARGET, "-o", OUTDIR+"/nmap_"+IPTARGET+".txt" ], "NMap simple", IPTARGET, 0, on_nmap_stdout_read)
    add_process([ "nmap",  "-sC",  "-sV",  "-A", IPTARGET, "-o", OUTDIR+"/nmap_"+IPTARGET+"_recon.txt" ], "NMap recon", IPTARGET, 0, on_nmap_stdout_read, on_process_finished)
    add_process(shlex.split("nmap -sV -p- "+IPTARGET+" -o "+OUTDIR+"/nmap_"+IPTARGET+"_all_tcp.txt"), "NMap all TCP", IPTARGET, 0, on_nmap_stdout_read, on_process_finished)
    add_process(shlex.split("nmap -sU -p- "+IPTARGET+" -o "+OUTDIR+"/nmap_"+IPTARGET+"_all_udp.txt"), "NMap all UDP", IPTARGET, 0, on_nmap_stdout_read, on_process_finished)



    while process_count > 0:
        description, rc= results.get()    
        process_count-= 1
        print "["+str(process_count)+"] Task ended : "+description
        

    #
    # Restore stdin/stdout
    #print "En cas de pb: stty echo"
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__
    os.system("stty echo")



def exit_gracefully(signum, frame):
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
    signal.signal(signal.SIGINT, original_sigint)
    print "-- Running tasks --"
    for p in procs:
        print "- "+p.title

    try:
        if raw_input("\nReally quit? (y/n)> ").lower().startswith('y'):
            for p in procs:
                print "Killing "+p.title
                p.kill()

            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            os.system("stty echo")
            sys.exit(1)

    except KeyboardInterrupt:
        print("Ok ok, quitting")
        for p in procs:
            p.kill()

        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        os.system("stty echo")
        sys.exit(1)

    # restore the exit gracefully handler here    
    signal.signal(signal.SIGINT, exit_gracefully)

if __name__ == '__main__':
    # store the original SIGINT handler
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_gracefully)
    run_program()