#!/usr/bin/python

"""
This program runs a query against the ProofPoint and  blocked database to
check if our MTA servers are listed.
"""

import re, urllib2, getopt, sys, subprocess, time, socket
#import cProfile

def main():

    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    victorops_url = 'https://alert.victorops.com/integrations/generic/20131114/alert/<API_KEY>'

    # Add IP 127.0.0.2 to test blocked message, remove it and add the MTA's IP Address
    mta_servers = ["127.0.0.2"]
    try:
        verbose = False
        standalone = False
        opts, args = getopt.getopt(sys.argv[1:], ":hvs", ['help','verbose','standalone'])
        for opt, arg in opts:
            if opt in ('-v', '--verbose'):
                verbose = True
            elif opt in ('-h', '--help'):
                usage()
                sys.exit()
            elif opt in ('-s', '--standalone'):
                standalone = True
            else:
                usage()
                sys.exit()

        if verbose:
            print ".:: Checking Proof Point ::."
        for ipaddress in mta_servers:
          if verbose:
              print "Checking : " + ipaddress
          page = urllib2.urlopen("https://support.proofpoint.com/dnsbl-lookup.cgi?ip=" + ipaddress).read()
          match = re.findall('This IP Address is currently being blocked', page)

          if not match:
            if verbose:
                print "Done - Status [" + OKGREEN + "Not Blocked" + ENDC + "]"
          else:
            dnshostname,alias,addresslist = lookup(ipaddress)
            print dnshostname
            if not standalone:
                _message_type = "WARNING"
                _entity_id = "Hostname [" + dnshostname + " - "  + ipaddress + "] is currently being blocked, Please checking in https://support.proofpoint.com/dnsbl-lookup.cgi?ip=" + ipaddress
                _state_message = "I felt a great disturbance in the Force, Please checking in https://support.proofpoint.com/dnsbl-lookup.cgi?ip="+ ipaddress
                send_to_victorops(_message_type, _entity_id, _state_message)
            if verbose:
                print "Done - Status [" + FAIL + dnshostname + " - " +ipaddress + " is blocked, please checking in https://support.proofpoint.com/dnsbl-lookup.cgi?ip=" + ipaddress + ENDC + "]"

        if verbose:
            print "\n.:: Checking MxToolBox servers ::."
        for m1_mta in mta_servers:
            for server_name in server_list():
                ipaddress_reversedns = revers_address(m1_mta, server_name)
                p = subprocess.Popen(['/usr/bin/dig','+short', ipaddress_reversedns], stdout=subprocess.PIPE)
                out, err = p.communicate()
                if "127.0.0.2" in out:
                    ip = str(m1_mta)
                    dnshostname,alias,addresslist = lookup(ipaddress)
                    if verbose:
                        print ipaddress_reversedns
                        print FAIL + "Hostname [" + dnshostname + " - " + ip + "] is currently being blocked, Please checking in http://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + ip + "&run=toolpage" + ENDC
                    if not standalone:
                        _message_type = "WARNING"
                        _entity_id = "Hostname [" + dnshostname + " - " + ip + "] is currently being blocked on " + ipaddress_reversedns
                        _state_message = "I felt a great disturbance in the Force, Please checking in http://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + ip + "&run=toolpage"
                        send_to_victorops(_message_type, _entity_id, _state_message)
                else:
                    if verbose:
                        print '{0: <45}'.format(ipaddress_reversedns) + "\t[" + OKGREEN + "Not Blocked"  + ENDC + "]"
                    continue


    except Exception as e:
        print FAIL + "Exception: " + str(e) + ENDC


def send_to_victorops( _message_type, _entity_id, _state_message ):

    ts = int(time.time())
    url = victorops_url
    data = '{"message_type":"'+ _message_type +'","timestamp":"' + str(ts) + '","entity_id":"' + _entity_id + '","state_message":"' + _state_message + '"}'
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    victorops_return = response.read()

    return victorops_return

def revers_address(ipaddress, domain):

    m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)',ipaddress)
    ip = m.group(4),m.group(3),m.group(2),m.group(1)

    return '.'.join(ip) + "." + domain

def lookup(addr):
    try:
      return socket.gethostbyaddr(addr)
    except socket.herror:
      return None, None, None

def server_list():

    server_list = ["all.s5h.net","b.barracudacentral.org","bl.deadbeef.com","bl.emailbasura.org",
                    "bl.spamcannibal.org","bl.spamcop.net","blackholes.five-ten-sg.com","blacklist.woody.ch",
                    "bogons.cymru.com","cbl.abuseat.org","cdl.anti-spam.org.cn","combined.abuse.ch",
                    "combined.rbl.msrbl.net","db.wpbl.info","dnsbl-1.uceprotect.net","dnsbl-2.uceprotect.net",
                    "dnsbl-3.uceprotect.net","dnsbl.anticaptcha.net","dnsbl.cyberlogic.net",
                    "dnsbl.dronebl.org","dnsbl.inps.de","dnsbl.njabl.org","dnsbl.sorbs.net","drone.abuse.ch",
                    "duinv.aupads.org","dul.dnsbl.sorbs.net","dul.ru","dyna.spamrats.com",
                    "dynip.rothen.com","exitnodes.tor.dnsbl.sectoor.de","http.dnsbl.sorbs.net","images.rbl.msrbl.net",
                    "ips.backscatterer.org","ix.dnsbl.manitu.net","korea.services.net","misc.dnsbl.sorbs.net",
                    "noptr.spamrats.com","ohps.dnsbl.net.au","omrs.dnsbl.net.au","orvedb.aupads.org",
                    "osps.dnsbl.net.au","osrs.dnsbl.net.au","owfs.dnsbl.net.au","owps.dnsbl.net.au",
                    "pbl.spamhaus.org","phishing.rbl.msrbl.net","probes.dnsbl.net.au","proxy.bl.gweep.ca",
                    "proxy.block.transip.nl","psbl.surriel.com","rbl.interserver.net","rbl.megarbl.net",
                    "rdts.dnsbl.net.au","relays.bl.gweep.ca","relays.bl.kundenserver.de","relays.nether.net",
                    "residential.block.transip.nl","ricn.dnsbl.net.au","rmst.dnsbl.net.au","sbl.spamhaus.org",
                    "service.mailblacklist.com","short.rbl.jp","singular.ttk.pte.hu","smtp.dnsbl.sorbs.net",
                    "socks.dnsbl.sorbs.net","spam.abuse.ch","spam.dnsbl.sorbs.net","spam.rbl.msrbl.net",
                    "spam.spamrats.com","spambot.bls.digibase.ca","spamlist.or.kr","spamrbl.imp.ch",
                    "spamsources.fabel.dk","t3direct.dnsbl.net.au","ubl.lashback.com",
                    "ubl.unsubscore.com","virbl.bit.nl","virus.rbl.jp","virus.rbl.msrbl.net",
                    "web.dnsbl.sorbs.net","wormrbl.imp.ch","xbl.spamhaus.org","zen.spamhaus.org",
                    "zombie.dnsbl.sorbs.net","bad.psky.me"]

    return server_list

def usage():

    usage = """
    Usage: check_dnsbl.py [options]

    Options:
        -h --help         Prints this
        -s --standalone   Disable VictorOps Notification
        -v --verbose      Execute in verbose mode
	"""
    print usage


if __name__ == "__main__":
    #
    #cProfile.run('main()')
    main()
