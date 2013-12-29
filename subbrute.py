#!C:\Python33\python.exe
'''
!/usr/bin/python

SubBrute v1.0
A (very) fast subdomain enumeration tool.

Written by Rook
Forked by jeremyBass
Forked by Alexander Riccio

"\'if done is not None\' is faster than \'if done != None\', which in turn is faster than \'if not done\'." - http://www.clips.ua.ac.be/tutorials/python-performance-optimization

'''
from __future__ import print_function
import re
import time
import optparse
import os
import signal
import sys
import random
import dns.resolver
import platform
import logging

'''
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
'''
from threading import Thread
import math



#support for python 2.7 and 3
v = platform.python_version().split('.')
if v[0].isdigit():
    if int(v[0]) < 3:
        import Queue as queue
    else:
        import queue

#if platform.python_version()
#try:
#    import queue
#except ImportError:
#    import Queue as queue
    

logging.basicConfig(level=logging.INFO)

NO_OUTPUT  = True
DEBUG_MODE = True

def killme(_, _unused):
    '''exit handler for signals.  So ctrl+c will work,  even with py threads. '''
    del _, _unused
    os.kill(os.getpid(), 9)

class lookup(Thread):
    '''an object that represents a single lookup thread'''
    def __init__(self, in_q, out_q, domain, tid, wildcard = False, resolver_list = []):
        Thread.__init__(self)
        self.__in_q = in_q
        self.__out_q = out_q
        self.__domain = domain
        self.__wildcard = wildcard
        self.__resolver_list = resolver_list
        self.__resolver = dns.resolver.Resolver()
        self.__tid = tid
        if len(self.__resolver.nameservers) > 0:
            self.backup_resolver = self.__resolver.nameservers
        else:
            #we must have a resolver,  and this is the default resolver on my system...
            self.backup_resolver = ['127.0.0.1']
        if len(self.__resolver_list) > 0:
            self.__resolver.nameservers = self.__resolver_list
        logging.debug(str('\t\tlookup thread instantiated! thread : ' + str(self.__tid)))

    def check(self, host):
        '''Query DNS resolver(s), if no answer or timeout, backoff  2^numTries '''
        slept = 0
        logging.debug(str('\t\t\tthread ' + str(self.__tid) + ' checking \'' + str(host) + '\''))
        while True:
            try:
                answer = self.__resolver.query(host)
                logging.debug(str('\t\t\t\tthread ' + str(self.__tid) + ' got answer: \'' + str(answer[0]) + '\' for host: \'' + str(host) + '\'!'))
                if answer:
                    return str(answer[0])
                else:
                    return False
            except Exception as e:
                if type(e) == dns.resolver.NXDOMAIN:
                    logging.debug(str('\t\t\t\tthread ' + str(self.__tid) + ' couldn\'t resolve host: \'' + str(host) + '\'!'))
                    return False

                elif type(e) == dns.resolver.NoAnswer  or type(e) == dns.resolver.Timeout:
                    if slept == 4:
                        #This dns server stopped responding.
                        #We could be hitting a rate limit.
                        if self.__resolver.nameservers == self.backup_resolver:
                            #if we are already using the backup_resolver use the resolver_list
                            self.__resolver.nameservers = self.__resolver_list
                        else:
                            #fall back on the system's dns name server
                            self.__resolver.nameservers = self.backup_resolver
                    elif slept > 5:
                        #hmm the backup resolver didn't work, 
                        #so lets go back to the resolver_list provided.
                        #If the self.backup_resolver list did work, lets stick with it.
                        self.__resolver.nameservers = self.__resolver_list
                        #I don't think we are ever guaranteed a response for a given name.
                        return False
                    #Hmm,  we might have hit a rate limit on a resolver.
                    logging.info('\t\tthread ' + str(self.__tid) +':\twe might have hit a rate limit on a resolver!')
                    logging.info('\t\tthread ' + str(self.__tid) + ':\tsleeping ' + str(math.pow(2,slept)))
                    time.sleep(math.pow(2, slept))
                    slept += 1
                    #retry...
                elif type(e) == IndexError:
                    #Some old versions of dnspython throw this error,
                    #doesn't seem to affect the results,  and it was fixed in later versions.
                    pass
                elif type(e) == dns.resolver.YXDOMAIN:
                    #the query name is too long after DNAME substitution
                    pass
                elif type(e) == dns.resolver.NoNameServers:
                    #no non-broken nameservers are available to answer the question
                    print("thread " + self.__tid + ":\tNoNameServers!", file=sys.stderr)
                else:
                    #dnspython threw some strange exception...
                    raise e

    def run(self):
        '''this method OVERRIDES threading.thread.run(self)
            run def from threading.thread:
                 |  run(self)
                 |      Method representing the thread's activity.
                 |      
                 |      You may override this method in a subclass. The standard run() method
                 |      invokes the callable object passed to the object's constructor as the
                 |      target argument, if any, with sequential and keyword arguments taken
                 |      from the args and kwargs arguments, respectively.'''

        while True:
            sub = self.__in_q.get()
            if not sub:
                logging.debug('\t\t\tthread ' + str(self.__tid) + ':\tnot sub!')
                #Perpetuate the terminator for all threads to see
                self.__in_q.put(False)
                #Notify the parent of our death of natural causes.
                self.__out_q.put(False)
                break
            else:
                test = "%s.%s" % (sub, self.__domain)
                #logging.debug('\n\t\tthread ' + str(self.__tid) +':\tTesting ' + str(test) + ' ......\n')
                addr = self.check(test)
                if addr and addr != self.__wildcard:
                    logging.debug('\t\t\t\tthread ' + str(self.__tid) + ':\t\''+ str(test) + '\' is valid! putting in out_q')
                    self.__out_q.put(test)


def extract_subdomains(file_name):
    '''Returns a list of unique sub domains (from given file),  sorted by frequency'''
    subs = {}
    with open(file_name) as inputFile:
        sub_file = inputFile.read()
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
    logging.debug('\t ' + 'check_resolvers(file_name) passed: ' + file_name)
    ret = []
    lines = []
    lineClean = []    
    resolver = dns.resolver.Resolver()
    with open(file_name, 'r') as res_file:
        for line in res_file:
            if (line != '') and (line != '\n'):
                lines.append(line)
    
    for line in lines:
        lineSplit = line.split('\n')
        lineProc  = [None, None]

        for word in lineSplit:
            if lineSplit.index(word) == 0:
                lineProc[0] =  word[0:len(word)]

            elif lineSplit.index(word) == 1:
                lineProc[1] = word
        lineClean.append(lineProc[0])
        
    #print( str('for method lines: ' + str(lineClean)))
    
    #res_file = open(file_name).read()
    #for server in res_file.split("\n"):
        #server = server.strip()
    logging.debug('\t\tfor all servers in list of resolvers, resolver.nameservers = ' + str(lineClean))
    for server in lineClean:
        resolver.nameservers = [server]
        try:
            resolver.query("www.google.com")
            #should throw an exception before this line.
            ret.append(server)
        except dns.resolver.NXDOMAIN:
            logging.warning('\n\tWARNING! ' + __name__ + ' ran into exception with info:  ' + str(sys.exc_info()) + '''sys.exc_info()[1] + sys.exc_info()[] +''' ' while checking resolvers')
        except:
            logging.warning('\n\tWARNING! ' + __name__ + ' ran into exception with info:  ' + str(sys.exc_info()) + '''sys.exc_info()[1] + sys.exc_info()[] +''' ' while checking resolvers')
            logging.warning(sys.exc_type)
            logging.warning(sys.exc_value)
            logging.warning(sys.exc_traceback)
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
    if thread_count < 1:
        logging.warning(__name__ + ' passed thread_count: ' + str(thread_count) + ' - we NEED at least 1 thread. Setting thread_count to 1')
        thread_count = 1
    if len(hosts) < 100:
        logging.debug('begin ' + 'run_target(target, hosts, resolve_list, thread_count, aFile, noOutput)' + ' passed: ' + str(target) + ' ' + str(hosts) + ' ' + str(resolve_list) + ' ' + str(thread_count) + ' ' + str(aFile) + ' ' + str(noOutput))
    elif len(hosts) >=99:
        logging.debug('begin ' + 'run_target(target ' + str(target) + ', hosts' + '<huge hosts list! Omitting it!> , resolve_list ' + str(resolve_list) + ', thread_count ' + str(thread_count) +  ', aFile ' + str(aFile) + ', noOutput ' + str(noOutput))
    try:
        resp = dns.resolver.Resolver().query(target)
        
    except dns.resolver.NXDOMAIN:
        print('CRITICAL: Domain  ( ' + target + ' ) not found!', file=sys.stderr)
        print('I can\'t find domain ( ' + target + ' )! I can\'t check for subdomains of an unknown domain!')
        return
    #The target might have a wildcard dns record...
    wildcard = False
    try:
        #hasWildcard = False
        resp = dns.resolver.Resolver().query('would-never-be-a-fucking-domain-name-' + str(random.randint(1, 9999)) + '.' + target)
        wildcard = str(resp[0])
        logging.debug('wildcard got ' + str(wildcard) +'\n\n')
    except dns.resolver.NXDOMAIN:
        logging.debug('wildcard got ' + str(wildcard) +'\n\n')
        logging.info("Target ( " + str(target) + " ) doesn't seem to redirect nonsense subdomains! (else our results would be invalid)")
        #hasWildcard = False
    except:
        logging.error('\n\tWARNING! ' + __name__ + ' ran into exception with info:  ' + str(sys.exc_info()) + '''sys.exc_info()[1] + sys.exc_info()[] +''' ' while checking for wildcards')
    if wildcard != ("" or False):
        logging.warning('wildcard !="" : ' + str(wildcard))
        print("Target ( " + target + " ) seems to redirect nonsense subdomains! (our results will be invalid!) Skipping")
        return
    in_q = queue.Queue()
    out_q = queue.Queue()
    for h in hosts:#puts all known subdomains into in_q
        logging.debug('\t\t\tputting h ' + str(h) + ' from hosts into in_q')
        in_q.put(h)
    #Terminate the queue
    in_q.put(False)
    step_size = int(len(resolve_list) / thread_count)
    logging.debug('\tchose step size: ' + str(step_size))
    #Split up the resolver list between the threads. 
    if step_size <= 0:
        step_size = 1
    step = 0
    threads = []
    logging.debug('\t                                                lookup( ' + 'target,\t\t' + 'wildcard,\t' + 'resolve_list[step:step + step_size]' +' )')
    for tid in range(thread_count):#underscore is python convention for unused variable
        logging.debug('\tAppending new lookup object to list of threads, lookup( ' + str(target) + ',\t' + str(wildcard) + ',\t\t' + str(resolve_list[step:step + step_size]) +' )')
        threads.append( lookup( in_q, out_q, target, tid,  wildcard , resolve_list[step:step + step_size] ) )
        threads[-1].start()
    logging.debug('\tstep (now ' + str(step) + ') incrementing by step_size (' + str(step_size) + ')')
    step += step_size
    if step >= len(resolve_list):
        step = 0

    threads_remaining = thread_count
    while True:
        try:
            d = out_q.get(True, 2)

            #debugHelp('\t\t\tIt looks like this thread has exhausted it\'s queue')
            #we will get an empty exception before this runs. 
            if not d:
                logging.info('Not d! - d=' + str(d))
                threads_remaining -= 1
            else:
                print(d)
                if d:
                    pass
                if not noOutput:
                    print_to_file(d,aFile)
        except queue.Empty:
            #debugHelp('\t\t\tA thread has exhausted it\'s q of subdomains to bruteforce')
        #make sure everyone is complete
            if threads_remaining <= 0:
                logging.info('No threads remaining!')
                break


'''
def send_mail(send_from, send_to, subject, text, files=[], server="localhost"):
    \'\'\'sends output file to given email addr\'\'\'
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
'''

def main():
    parser = optparse.OptionParser("usage: %prog [options] target")
    parser.add_option("-c", "--thread_count", dest = "thread_count", default = 10,
              type = "int", help = "(optional) Number of lookup theads to run,  more isn't always better. default=10")
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
    parser.add_option("-d", "--debug", dest = "debugMode", default = "",
              type  = "string", help = "for the curious...")
    (options, args) = parser.parse_args()
    if options.debugMode != "":
        debugHelp = isDebugger(True)
    else:
        debugHelp = isDebugger(False)
    logging.debug('\ndebugger passed options: ' + str(options))
    logging.debug('debugger passed args: '    + str(args))
    if len(args) < 1 and options.filter == "" and options.targets == "":
        parser.error("You must provide a target! Use -h for help.")

    if options.filter != "":
        #cleanup this file and print it out
        for d in extract_subdomains(options.filter):
            print(d)
        sys.exit()

    if options.targets != "":
        targets = open(options.targets).read().split("\n")
        logging.info('options.targets !="", targets = ' + str(targets))
    else:
        targets = args #multiple arguments on the cli:  ./subbrute.py google.com gmail.com yahoo.com
        logging.debug('"[...]arguments on the cli", targets = ' + str(targets))
        #TODO: wtf is actually going on here
                  
    hosts = open(options.subs).read().split("\n")
    if len(hosts) < 100:
        logging.debug('hosts = ' + str(hosts))
    elif len(hosts) > 99:
        logging.debug('hosts = a really damn big list, so big that I\'m omitting it!')
    logging.info('Checking resolvers...')
    resolve_list = check_resolvers(options.resolvers)
    logging.debug('main() got list of resolvers: ' + str(resolve_list) + ' from check_resolvers')
    #threads = []#is this even needed?
    signal.signal(signal.SIGINT, killme)

    for target in targets:
        target = target.strip()
        
        if target:
            if options.output_file != "":
                run_target(target, hosts, resolve_list, options.thread_count, options.output_file, not NO_OUTPUT)
            elif options.output_file == "":
                run_target(target, hosts, resolve_list, options.thread_count, options.output_file, NO_OUTPUT)
            #if options.sendto_email != "":
                #send_mail(options.sendto_email,options.sendto_email,"domains","text",[options.output_file], "localhost")

def isDebugger(boolVal):
    '''ugly hack for debugging - this is MAJOR code smell!'''
    if boolVal:
        def debugHelp(*args):
            '''if DEBUG_MODE == True, this function prints parameter(s) to screen'''
            stringToPrint = ''
            for arg in args:
                stringToPrint += str(arg)
            print(stringToPrint)
        return debugHelp
    else:
        def debugHelp(*args):
            pass
        return debugHelp


if __name__ == "__main__":

    main()
