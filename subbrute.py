#!C:\Python33\python.exe
'''
!/usr/bin/python

SubBrute v1.0
A (very) fast subdomain enumeration tool.

Written by Rook
Forked by jeremyBass
Forked by Alexander Riccio

"'if done is not None' is faster than 'if done != None', which in turn is faster than 'if not done'." - http://www.clips.ua.ac.be/tutorials/python-performance-optimization

'''
#TODO: get rid of optparse!
from __future__ import print_function
import re
import time
import optparse#depreciated
import argparse
import os
import signal
import sys
import random
import dns.resolver
import platform
import logging
import timeit

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

RESOLVE_NUM_THREADS = 3
#support for python 2.7 and 3
if sys.version_info.major < 3:
    import Queue as queue
elif sys.version_info.major > 2:
    import queue    

#logging.basicConfig(level=logging.WARN)

def killme(_, _unused):
    '''exit handler for signals.  So ctrl+c will work,  even with py threads. '''
    del _, _unused
    os.kill(os.getpid(), 9)

class lookup(Thread):
    '''an object that is a single lookup thread'''
    def __init__(self, in_q, out_q, domain, tid, wildcard = False, resolver_list = []):#resolver_list is misleading, is currently only single resolver per thread
        Thread.__init__(self)
        self.__in_q = in_q
        self.__out_q = out_q
        self.__domain = domain
        if wildcard == None:
            wildcard = False
        self.__wildcard = wildcard
        self.__resolver_list = resolver_list
        self.__resolver = dns.resolver.Resolver()
        self.__tid = int(tid)
        if len(self.__resolver.nameservers) > 0:
            self.backup_resolver = self.__resolver.nameservers
        else:
            #we must have a resolver,  and this is the default resolver on my system...
            self.backup_resolver = ['127.0.0.1']
        if len(self.__resolver_list) > 0:
            self.__resolver.nameservers = self.__resolver_list
        logging.debug(str('\t\tlookup thread instantiated! thread : %i' % self.__tid))

    def check(self, host):
        '''Query DNS resolver(s), if no answer or timeout, backoff  2^numTries '''
        #TODO: refactor this method
        slept = 0
        logging.debug('\t\t\tthread %i checking \'%s\' with resolver %s'% (self.__tid, host,str(self.__resolver_list)) )
        domain_match = re.compile("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
        while True:
            try:
                answer = self.__resolver.query(host)
                self.__ansZero = str(answer[0])
                logging.debug('\t\t\t\tthread %i got answer: \'%s\' for host: \'%s\' with resolver %s!'%(self.__tid, self.__ansZero, host,str(self.__resolver_list)))
                if answer is not None:
                    isValidIP = re.match(domain_match, self.__ansZero)
                    if isValidIP is not None:
                        logging.debug('\t\t\t\t\t%s matches valid IP' % self.__ansZero)
                    return self.__ansZero
                else:
                    return False
            except dns.resolver.NXDOMAIN:
                logging.debug('\t\t\t\tthread %i couldn\'t resolve host: \'%s\' with resolver %s!'%(self.__tid, host, str(self.__resolver_list)))
                return False

            except (dns.resolver.NoAnswer, dns.resolver.Timeout):
                if slept == 3:
                    logging.debug('This is the fourth time we\'ve Timed out or hit a rate limit!')
                    #This dns server stopped responding. We could be hitting a rate limit.
                    if self.__resolver.nameservers == self.backup_resolver:
                        #if we are already using the backup_resolver use the resolver_list
                        self.__resolver.nameservers = self.__resolver_list
                    else:
                        #fall back on the system's dns name server
                        self.__resolver.nameservers = self.backup_resolver
                elif slept > 3:
                    #hmm the backup resolver didn't work, so lets go back to the resolver_list provided.
                    #If the self.backup_resolver list did work, lets stick with it.
                    self.__resolver.nameservers = self.__resolver_list
                    return False
                
                logging.info('\t\tthread %i:\twe might have hit a rate limit on a resolver! (while testing host: %s)' % (self.__tid, host))
                self.__sleepTime = math.pow(2,slept)
                logging.info('\t\tthread %i:\tsleeping %i' % (self.__tid, self.__sleepTime))
                time.sleep(self.__sleepTime)
                slept += 1
                #retry...
            except IndexError:
                #Some old versions of dnspython throw this error, doesn't seem to affect the results,  and it was fixed in later versions.
                pass
            except dns.resolver.YXDOMAIN:
                #the query name is too long after DNAME substitution
                pass
            except dns.resolver.NoNameservers:
                #no non-broken nameservers are available to answer the question
                logging.error("thread %i:\tNoNameservers while checking host: %s!" % (self.__tid, host))
                return False
            except AttributeError:
                #logging.CRITICAL('wtf')
                #killme(None,None)
                logging.error(sys.exc_info())
                sys.exit(self.__tid)
                os.abort() #abort so I know there is an error to be debugged!
##            except:
##                #dnspython threw some strange exception...
##                logging.error('Unknown exception in thread %i! Something is very wrong!' % self.__tid)
##                #logging.error('line #: %i' % self.Frame.f_lineno)
##                logging.warning(sys.exc_info())
##                logging.debug(sys.exc_info()[2])
##                sys.exit(self.__tid)

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

        logging.debug('thread %i running!'% self.__tid)
        while True:
            sub = self.__in_q.get()
            if not sub:
                logging.debug('\t\t\tthread %i:\tnot sub!,  sub = %s'% (self.__tid, sub))
                logging.debug('type sub = %s' % str(type(sub)))
                if sub is None:
                    #me debugging method
                    logging.debug('\t\t\tthread %i:\tsub is None!'%(self.__tid))
                #Perpetuate the terminator for all threads to see
                self.__in_q.put(False)
                #Notify the parent of our death of natural causes.
                self.__out_q.put(False)
                break
            else:
                self.__test = "%s.%s" % (sub, self.__domain)
                try:
                    addr = self.check(self.__test)
                except AttributeError:
                    #logging.debug('wtf')
                    logging.error('attribute error while testing subdomain!')
                    logging.error(sys.exc_info())
                    os.abort()#abort so I know there is an error to be debugged!
                    #sys.exit(self.__tid)
                if addr and self.__wildcard == False:
                    logging.debug('\t\t\t\tthread %i :\t\' %s \' is valid! putting in out_q' % (self.__tid, self.__test))
                    self.__out_q.put(self.__test)
                    #domainDict[]


def extract_subdomains(file_name):
    '''Returns a list of unique sub domains (from given file),  sorted in descending order by frequency
       domain names can only be lowercase, so returned names are lowercase'd
       uses regex "([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+" to segment lines into subdomain.domain.tld
       
    '''
    subs = {}
    with open(file_name) as inputFile:
        sub_file = inputFile.read()
    #Only match domains that have 3 or more sections subdomain.domain.tld
    domain_match = re.compile("([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+")
    f_all = re.findall(domain_match, sub_file)
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
                for q in p:
                    if q :
                        q = q.lower()
                        if q in subs:
                            subs[q] += 1
                            logging.debug('subdomain %s has been seen %s times' % (q, str(subs[q])))
                        else:
                            logging.debug('subdomain %s seen for the first time' % q)
                            subs[q] = 1
                            
    subs_sorted = sorted(subs.keys(), key = lambda x: subs[x], reverse = True)
    return subs_sorted

def check_resolvers(file_name):
    '''validates list of DNS resolvers in given file_name, one per line
       uses my (to-be-improved) line processing algorithm
    '''
    #TODO: refactor this ugly function
    logging.debug('\t check_resolvers(file_name) passed: %s' % str(file_name))
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
        
    logging.debug('\t\tfor all servers in list of resolvers, resolver.nameservers = %s\n' % str(lineClean))
    resolverQuery = "www.google.com"
    for server in lineClean:
        resolver.nameservers = [server]
        try:
            logging.debug('\t\t\tChecking resolver %s...' % server )            
            resolver.query(resolverQuery)
            #should throw an exception before this line.
            ret.append(server)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            #logging.warning('\n\tWARNING! ' + __name__ + ' ran into exception with info:  ' + str(sys.exc_info()) + '''sys.exc_info()[1] + sys.exc_info()[] +''' ' while checking resolver ' + server)
            logging.debug('\t\t\t\tresolver %s failed to resolve %s, reason: %s' % (server, resolverQuery, str(sys.exc_info()[1])) )
            try:
                ret.remove(server)
            except ValueError:
                pass#never made it to the list in the first place!
##        except dns.resolver.NoNameservers:
##            #"No non-broken nameservers are available to answer the query."
##            logging.debug('\t\t\t\tresolver %s failed to resolve %s' % (server, resolverQuery) )
##            ret.remove(server)
        except KeyboardInterrupt:
            sys.exit('Caught keyboard interrupt!')
        except:
            logging.warning('\n\tWARNING! ' + __name__ + ' ran into exception with info:  ' + str(sys.exc_info()) + '''sys.exc_info()[1] + sys.exc_info()[] +''' ' while checking resolver ' + server)
            logging.warning(sys.exc_info())
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
    #TODO: refactor this ugly function
    if thread_count is None:
        thread_count = len(resolve_list)*RESOLVE_NUM_THREADS
        logging.debug('resolver list is %i resolver(s) long' % len(resolve_list))
        logging.debug('set thread count ( %i*%i ) to %i' % (len(resolve_list), RESOLVE_NUM_THREADS, thread_count ) )
    if thread_count < 1:
        logging.warning('%s passed thread_count: %i - we NEED at least 1 thread. Setting thread_count to 1' % (__name__, thread_count))
        thread_count = 1
    if len(hosts) < 100:
        logging.debug('begin ' + 'run_target(target, hosts, resolve_list, thread_count, aFile, noOutput)' + ' passed: ' + target + ' ' + str(hosts) + ' ' + str(resolve_list) + ' ' + str(thread_count) + ' ' + str(aFile) + ' ' + str(noOutput) + '\n')
    elif len(hosts) >=99:
        logging.debug('begin ' + 'run_target(target ' + target + ', hosts' + '<huge hosts list! Omitting it!> , resolve_list ' + str(resolve_list) + ', thread_count ' + str(thread_count) +  ', aFile ' + str(aFile) + ', noOutput ' + str(noOutput) + '\n')
    for resolver in resolve_list:
        try:
            resp = dns.resolver.Resolver().query(target)
            
        except dns.resolver.NXDOMAIN:
            logging.warning('Domain  ( %s ) not found!' % target)
            logging.warning('Resolver %s could not resolve target %s! removing from resolve_list' % (resolver, target))
            resolve_list.remove(resolver)
    if len(resolve_list) < 1:
        logging.error('No resolvers can resolve %s! I can\'t check for subdomains of an unknown domain!' % target)
        return queue.Queue()
    
    #The target might have a wildcard dns record...
    wildcardDict = {}
    for resolver in resolve_list:
        try:
            wildcard = str(False)
            buildQuery = str('would-never-be-a-fucking-domain-name-' + str(random.randint(1, 9999999)) + '.' + target)
            logging.debug('trying %s with resolver %s' % (buildQuery, resolver))
            resp = dns.resolver.Resolver().query(buildQuery)
            wildcard = str(resp)
            logging.debug('wildcard got %s' % wildcard)
            wildcardDict[str(resolver)] = True
        except dns.resolver.NXDOMAIN:
            logging.debug('\tresolver threw NXDOMAIN; Wildcard got %s' % wildcard)
            logging.debug("\t\tTarget ( " + target + " ) doesn't seem to redirect nonsense subdomains with resolver " + resolver + "! (else our results would be invalid)")
            logging.debug('\t\t\tadding resolver %s to dict wildcardDict[%s] with value False\n' % (resolver,resolver))
            wildcardDict[str(resolver)] = False
            
        except:
            logging.error('\n' + __name__ + ' ran into exception with info:  ' + str(sys.exc_info()) + '''sys.exc_info()[1] + sys.exc_info()[] +''' ' while checking for wildcards')
        if wildcard != False and wildcard != "" and wildcard != str(False):
            logging.warning('resolver %s seems to redirect nonsense subdomains of target %s' % (resolver, target))
            logging.warning('removing resolver %s' % resolver)
            logging.debug('\t\t\tadding resolver %s to dict wildcardDict[%s] with value True' % (resolver,resolver))
            wildcardDict[str(resolver)] = True
            resolve_list.remove(resolver)
    logging.debug('contents of wildcardDict: ')
    logging.debug('\t[')
    for key in wildcardDict.iterkeys():
        logging.debug('\t\t [%s] = %s' % (key, str(wildcardDict[key])))
    logging.debug('\t\t\t]')
    logging.debug("resolvers that don't seem to redirect nonsense subdomains: %s\n" % str(resolve_list) )
    in_q = queue.Queue()
    out_q = queue.Queue()
    for h in hosts:#puts all known subdomains into in_q
        logging.debug('\t\t\tputting h %s from hosts into in_q' % h)
        in_q.put(h)
        
    #Terminate the queue
    in_q.put(False)
    step_size = int(len(resolve_list) / thread_count)
    logging.debug('\tchose step size: %i' % step_size)

    #Split up the resolver list between the threads. 
    if step_size <= 0:
        step_size = 1

    step = 0
    threads = []
    domainDict = {}
    wildcard = str(wildcard)
    
    logging.debug('\t                                                lookup( ' + 'target,\t\t' + 'wildcard,\t' + 'resolve_list[step:step + step_size]' +' )')
    for tid in range(thread_count):
        #logging.debug(str(step + step_size))
        thisResolve = str(resolve_list[step:step + step_size])
        logging.debug('resolve_list[%i] = %s' % ((step + step_size), thisResolve))
        logging.debug('wildcardDict[%s] = %s' % (str(resolve_list[step:step + step_size]), wildcardDict.get(thisResolve)))
        logging.debug('\tAppending new lookup object to list of threads, lookup( ' + target + ',\t' + str(wildcardDict.get(thisResolve)) + ',\t\t' + thisResolve +' )')
        threads.append( lookup( in_q, out_q, target, tid,  wildcardDict.get(thisResolve) , resolve_list[step:step + step_size] ) )
        threads[-1].start()
        logging.debug('\tstep (now %i) incrementing by step_size (%i)' % (step, step_size))
        step += step_size
        if step >= len(resolve_list):
            step = 0
    #d = []
    out = []
    threads_remaining = thread_count
    while True:
        #is this the best way to do it? #TODO
        try:
            d = out_q.get(True, 2)
            #we will get an empty exception before this runs. 
            if not d:
                logging.info('Not d! - d= %s' % str(d))
                threads_remaining -= 1
            else:
                print(d)
                if d:
                    pass
                if noOutput:
                    out.append(d)
                if noOutput == False:
                    print_to_file(d,aFile)
        except queue.Empty:
        #make sure everyone is complete
            if threads_remaining <= 0:
                logging.info('No threads remaining!')
                break
    return out

def main():
    parser = optparse.OptionParser("usage: %prog [options] target")
    parser.add_option("-c", "--thread_count", dest = "thread_count", default = None,
              type = "int", help = "(optional) Number of lookup theads to run,  more isn't always better. default=10")
    parser.add_option("-s", "--subs", dest = "subs", default = "subs.txt",
              type = "string", help = "(optional) list of subdomains,  default='subs.txt'")
    parser.add_option("-r", "--resolvers", dest = "resolvers", default = "resolvers.txt",
              type = "string", help = "(optional) A list of DNS resolvers, if this list is empty it will OS's internal resolver default='resolvers.txt'")
    parser.add_option("-f", "--filter_subs", dest = "filter", default = "",
              type = "string", help = "(optional) A file containing unorganized domain names which will be filtered into a list of subdomains sorted by frequency. List will be printed to stdout, and program will EXIT. This was used to build subs.txt.")
    parser.add_option("-t", "--target_file", dest = "targets", default = "",
              type = "string", help = "(optional) A file containing a newline delimited list of domains to brute force.")
    parser.add_option("-o", "--output_file", dest = "output_file", default = "",
              type = "string", help = "(optional) A file to output list")
    parser.add_option("-e", "--sendto_email", dest = "sendto_email", default = "",
              type = "string", help = "(optional) email to send file to")
    parser.add_option("-d", "--debug", dest = "debugMode", default = "",
              type = "string", help = "for the curious...")
    parser.add_option("-V", "--validate", dest = "validateByPing", default = "",
              type = "string", help = "after brute force lookup, attempts to validate found subdomains by pinging hosts ")

    (options, args) = parser.parse_args()
    
    if options.debugMode != "":
        logging.basicConfig(level=logging.DEBUG)
        print('Debug mode set!\n')
    else:
        logging.basicConfig(level=logging.WARN)
    logging.debug('debugger passed options: %s' % str(options))
    logging.debug('\ttype options: %s' % str(type(options)))
    logging.debug('debugger passed args: %s'      % str(args))
    logging.debug('\ttype args: %s' % str(type(args)))
    logging.debug('\ttype options.targets: %s' % str(type(options.targets)))
    if len(args) < 1 and options.filter == "" and options.targets == "":
        parser.error("You must provide a target! Use -h for help.")
        logging.critical('I don\'t know what to do!')
    if options.filter != "":
        for d in extract_subdomains(options.filter):
            print(d)
        sys.exit()

    if options.targets != "":
        targets = open(options.targets).read().split("\n")
        logging.debug('type of targets = %s' % str(type(targets)))
        logging.info('options.targets !="", targets = %s' % str(targets))
        print('\n\n\n\n\n\n\n\n\n\ttype targets: %s' % str(type(targets)))
    else:
        targets = args #multiple arguments on the cli:  ./subbrute.py google.com gmail.com yahoo.com
        logging.debug('"[...]arguments on the cli", targets = %s' % str(targets))
                  
    hosts = open(options.subs).read().split("\n")
    if len(hosts) < 100:
        logging.debug('hosts = %s' % str(hosts))
    elif len(hosts) > 99:
        logging.debug('hosts = a really damn big list, so big that I\'m omitting it!')
    logging.debug('Checking resolvers...')
    resolve_list = check_resolvers(options.resolvers)
    logging.debug('main() got list of resolvers: %s from check_resolvers\n' % (str(resolve_list)))
    signal.signal(signal.SIGINT, killme)

    for target in targets:
        target = target.strip()
            
        if target:
            if options.output_file != "":
                out_q = run_target(target, hosts, resolve_list, options.thread_count, options.output_file, False)
            elif options.output_file == "":
                out_q = run_target(target, hosts, resolve_list, options.thread_count, options.output_file, True)

    if options.debugMode != "" or options.validateByPing != "":
        print('\n\n\n\n\n')
        print(out_q)
        for host in out_q:
            os.system('ping -w 100 -n 1 %s' % host)

if __name__ == "__main__":
    main()
