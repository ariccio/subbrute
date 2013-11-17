#!C:\Python27\python.exe
'''
!/usr/bin/python

SubBrute v1.0
A (very) fast subdomain enumeration tool.

Written by Rook
Forked by jeremyBass
Forked by Alexander Riccio
'''
import re
import time
import optparse
import os
import signal
import sys
import random
import dns.resolver
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
from threading import Thread
#support for python 2.7 and 3
try:
    import queue
except:
    import Queue as queue


NO_OUTPUT = True



def killme():
    '''exit handler for signals.  So ctrl+c will work,  even with py threads. '''
    os.kill(os.getpid(), 9)

class lookup(Thread):
    '''instantiates new thread?'''
    def __init__(self, in_q, out_q, domain, wildcard = False, resolver_list = []):
        Thread.__init__(self)
        self.in_q = in_q
        self.out_q = out_q
        self.domain = domain
        self.wildcard = wildcard
        self.resolver_list = resolver_list
        self.resolver = dns.resolver.Resolver()
        if len(self.resolver.nameservers):
            self.backup_resolver = self.resolver.nameservers
        else:
            #we must have a resolver,  and this is the default resolver on my system...
            self.backup_resolver = ['127.0.0.1']
        if len(self.resolver_list):
            self.resolver.nameservers = self.resolver_list

    def check(self, host):
        slept = 0
        while True:
            try:
                answer = self.resolver.query(host)
                if answer:
                    return str(answer[0])
                else:
                    return False
            except Exception as e:
                if type(e) == dns.resolver.NXDOMAIN:
                    #not found
                    return False
                elif type(e) == dns.resolver.NoAnswer  or type(e) == dns.resolver.Timeout:
                    if slept == 4:
                        #This dns server stopped responding.
                        #We could be hitting a rate limit.
                        if self.resolver.nameservers == self.backup_resolver:
                            #if we are already using the backup_resolver use the resolver_list
                            self.resolver.nameservers = self.resolver_list
                        else:
                            #fall back on the system's dns name server
                            self.resolver.nameservers = self.backup_resolver
                    elif slept > 5:
                        #hmm the backup resolver didn't work, 
                        #so lets go back to the resolver_list provided.
                        #If the self.backup_resolver list did work, lets stick with it.
                        self.resolver.nameservers = self.resolver_list
                        #I don't think we are ever guaranteed a response for a given name.
                        return False
                    #Hmm,  we might have hit a rate limit on a resolver.
                    time.sleep(1)
                    slept += 1
                    #retry...
                elif type(e) == IndexError:
                    #Some old versions of dnspython throw this error,
                    #doesn't seem to affect the results,  and it was fixed in later versions.
                    pass
                else:
                    #dnspython threw some strange exception...
                    raise e

    def run(self):
        while True:
            sub = self.in_q.get()
            if not sub:
                #Perpetuate the terminator for all threads to see
                self.in_q.put(False)
                #Notify the parent of our death of natural causes.
                self.out_q.put(False)
                break
            else:
                test = "%s.%s" % (sub, self.domain)
                addr = self.check(test)
                if addr and addr != self.wildcard:
                    self.out_q.put(test)


def extract_subdomains(file_name):
    '''Returns a list of unique sub domains,  sorted by frequency'''
    subs = {}
    sub_file = open(file_name).read()
    #Only match domains that have 3 or more sections subdomain.domain.tld
    domain_match = re.compile("([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+")
    f_all = re.findall(domain_match, sub_file)
    del sub_file
    for i in f_all:
        if i.find(".") >= 0:
            p = i.split(".")[0:-1]
            #gobble everything that might be a TLD
            while p and len(p[-1]) <= 3:
                p = p[0:-1]
            #remove the domain name
            p = p[0:-1]
            #do we have a subdomain.domain left?
            if len(p) >= 1:
                #print(str(p) + " : " + i)
                for q in p:
                    if q :
                        #domain names can only be lower case.
                        q = q.lower()
                        if q in subs:
                            subs[q] += 1
                        else:
                            subs[q] = 1
    #Free some memory before the sort...
    del f_all
    #Sort by freq in desc order
    subs_sorted = sorted(subs.keys(), key = lambda x: subs[x], reverse = True)
    return subs_sorted

def check_resolvers(file_name):
    '''validates given list of DNS resolvers'''
    ret = []
    resolver = dns.resolver.Resolver()
    res_file = open(file_name).read()
    for server in res_file.split("\n"):
        server = server.strip()
        if server:
            resolver.nameservers = [server]
            try:
                resolver.query("www.google.com")
                #should throw an exception before this line.
                ret.append(server)
            except:
                pass
    return ret

def print_to_file(output,aFile):
    '''prints found domains to a file'''
    try:
        f = open(aFile,'a')
    except IOError:
        f = open(aFile,'w')
    f.write(output+'\n')
    f.close()


def run_target(target, hosts, resolve_list, thread_count, aFile, noOutput):
    '''run subdomain bruteforce lookup against a specified target domain'''
    #The target might have a wildcard dns record...
    wildcard = False
    try:

        resp = dns.resolver.Resolver().query("would-never-be-a-fucking-domain-name-" + str(random.randint(1, 9999)) + "." + target)
        wildcard = str(resp[0])
    except:
        pass
    in_q = queue.Queue()
    out_q = queue.Queue()
    for h in hosts:
        in_q.put(h)
    #Terminate the queue
    in_q.put(False)
    step_size = int(len(resolve_list) / thread_count)
    #Split up the resolver list between the threads. 
    if step_size <= 0:
        step_size = 1
    step = 0
    threads = []
    for _ in range(thread_count):#underscore is python convention for unused variable
        threads.append(lookup(in_q, out_q, target, wildcard , resolve_list[step:step + step_size]))
        threads[-1].start()
    step += step_size
    if step >= len(resolve_list):
        step = 0

    threads_remaining = thread_count
    while True:
        try:
            d = out_q.get(True, 10)
            #we will get an empty exception before this runs. 
            if not d:
                threads_remaining -= 1
            else:
                print(d)
                if not noOutput:
                    print_to_file(d,aFile)
        except queue.Empty:
            pass
        #make sure everyone is complete
        if threads_remaining <= 0:
            break



def send_mail(send_from, send_to, subject, text, files=[], server="localhost"):
    '''sends output file to given email addr'''
    assert type(send_to)==list
    assert type(files)==list

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach( MIMEText(text) )

    for f in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(f,"rb").read() )
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
        msg.attach(part)

    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()


def main():
    parser = optparse.OptionParser("usage: %prog [options] target")
    parser.add_option("-c", "--thread_count", dest = "thread_count",
              default = 10, type = "int",
              help = "(optional) Number of lookup theads to run,  more isn't always better. default=10")
    parser.add_option("-s", "--subs", dest = "subs", default = "subs.txt",
              type = "string", help = "(optional) list of subdomains,  default='subs.txt'")
    parser.add_option("-r", "--resolvers", dest = "resolvers", default = "resolvers.txt",
              type = "string", help = "(optional) A list of DNS resolvers, if this list is empty it will OS's internal resolver default='resolvers.txt'")
    parser.add_option("-f", "--filter_subs", dest = "filter", default = "",
              type = "string", help = "(optional) A file containing unorganized domain names which will be filtered into a list of subdomains sorted by frequency.  This was used to build subs.txt.")
    parser.add_option("-t", "--target_file", dest = "targets", default = "",
              type = "string", help = "(optional) A file containing a newline delimited list of domains to brute force.")
    parser.add_option("-o", "--output_file", dest = "output_file", default = "",
              type = "string", help = "(optional) A file to output list")
    parser.add_option("-e", "--sendto_email", dest = "sendto_email", default = "",
              type = "string", help = "(optional) email to send file to")

    (options, args) = parser.parse_args()

    if len(args) < 1 and options.filter == "" and options.targets == "":
        parser.error("You must provie a target! Use -h for help.")

    if options.filter != "":
        #cleanup this file and print it out
        for d in extract_subdomains(options.filter):
            print(d)
        sys.exit()

    if options.targets != "":
        targets = open(options.targets).read().split("\n")
    else:
        targets = args #multiple arguments on the cli:  ./subbrute.py google.com gmail.com yahoo.com

    hosts = open(options.subs).read().split("\n")

    resolve_list = check_resolvers(options.resolvers)
    #threads = []#is this even needed?
    signal.signal(signal.SIGINT, killme)

    for target in targets:
        target = target.strip()
        if target:
            if options.output_file != "":
                run_target(target, hosts, resolve_list, options.thread_count, options.output_file, not NO_OUTPUT)
            elif options.output_file == "":
                run_target(target, hosts, resolve_list, options.thread_count, options.output_file, NO_OUTPUT)
            if options.sendto_email != "":
                send_mail(options.sendto_email,options.sendto_email,"domains","text",[options.output_file], "localhost")


if __name__ == "__main__":
    main()
