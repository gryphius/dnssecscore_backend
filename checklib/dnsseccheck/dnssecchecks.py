from __future__ import print_function
import time
from dns.dnssec import algorithm_to_text


NXDOMAIN = None
RESULTTYPE_UNKNOWN = "unknown"
RESULTTYPE_GOOD = "good"
RESULTTYPE_WARNING = "warning"
RESULTTYPE_BAD = "bad"
RESULTTYPE_NEUTRAL = "neutral"

TESTRESULTTYPE_TRUSTISSUE = "T"
TESTRESULTTYPE_INSECURE = "I"
TESTRESULTTYPE_VALIDATIONFAILURE = "F"
TESTRESULTTYPE_SECURE = "S"
TESTRESULTTYPE_ERROR = "E"

from dnsdict import dnsdict, dshash
import sys

all_tests = []

class DNSInfoBroker(object):
    def __init__(self, domain = None):
        self.domaininfo={}
        self.domain = domain

        if self.domain!=None:
            self._load_info()

    def _load_info(self):
        self.domaininfo = dnsdict(self.domain)

    def have_completed(self, rtype):
        return True

    def is_nxdomain(self, rtype): #or empty
        rtype = rtype.upper()
        if  self.domaininfo['LOCAL_DNSSEC'][rtype]['_META']['i_rcode'] == 3:
            return True
        if  rtype not in self.domaininfo['LOCAL_DNSSEC'][rtype]: # no answer for this query
            return True

        val = self.domaininfo['LOCAL_DNSSEC'][rtype][rtype]

        if val == None:  # value = None is treated the same way as no key
            return True

        if len(val)== 0: # empty list is treated the same way
            return True

        return False

    def get_records(self, rtype):
        rtype = rtype.upper()
        answers =  self.domaininfo['LOCAL_DNSSEC'][rtype]
        if rtype in answers:
            return answers[rtype]
        else:
            return []

    def get_rrsigs(self, rtype):
        rtype = rtype.upper()
        return self.domaininfo['LOCAL_DNSSEC'][rtype]['RRSIG']

class TestBase(object):
    def __init__(self,broker):
        self.name="dummy test name"
        self.description="test description"
        self.broker = broker

        self.shortcircuit = None # set a TESTRESULTTYPE_... to abort all tests

        self.result_type = RESULTTYPE_UNKNOWN
        self.result_weight = 1 # how important is this test. 0 for "informative only", 1 is standard
        self.result_score = None # set this in run_test.None means: let the test engine decide based on the test result ("auto"). 0 means completely failed, 1 means everything passed. more than 1 means "extra points"
        self.result_messages = []


    def do_we_have_what_we_need(self):
        #ask the broker if the records have been completed
        return True

    def run_test(self):
        pass


# the real tests
class AreWeSigned(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "DNSSEC enabled"
        self.description = "look for DNSKEY records in the domain"

    def do_we_have_what_we_need(self):
        if not self.broker.have_completed('DNSKEY'):
            return False
        return True

    def run_test(self):
        if self.broker.is_nxdomain('DNSKEY'):
            self.result_type = RESULTTYPE_BAD
            self.shortcircuit = TESTRESULTTYPE_INSECURE
            self.result_messages.append("No DNSKEY records in %s"%self.broker.domain)
            return
        self.result_type = RESULTTYPE_GOOD
all_tests.append(AreWeSigned)


class HaveDS(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Secure delegation"
        self.description = "Fetch DS records from the parent domain"

    def do_we_have_what_we_need(self):
        if not self.broker.have_completed('DS'):
            return False
        return True

    def run_test(self):
        if self.broker.is_nxdomain('DS'):
            self.result_type = RESULTTYPE_BAD
            self.shortcircuit = TESTRESULTTYPE_TRUSTISSUE
            self.result_messages.append("No DS records for %s. This probably means that this domain is an island of security and we can not actually verify it"%self.broker.domain)
            return

        dsrec = self.broker.get_records('DS')
        dskeytags = set([ds['key_tag'] for ds in dsrec])
        numds = len(dskeytags)
        self.result_messages.append("found %s DS records" % numds)
        if numds>2:
            self.result_messages.append("More than two DS records are pointless")
            self.result_weight = 0.8
            self.result_type = RESULTTYPE_WARNING
            return

        self.result_type = RESULTTYPE_GOOD
all_tests.append(HaveDS)

class DSDigestAlgo(TestBase):
    """Check DS Algorithms
    For *every* KSK key tag with a corresponding DS the DS must have a correct SHA2 digest


    Test:
     - get all key tags
     - get all DS records
     - for every key tag where there is at least one matching DS key tag:
            - if the digest is not correct, the max score is "WARN", we can not return "GOOD"
            - if the digest is type 2, this particular key tag is ok
     - if all key tags are ok, the result is GOOD, BAD otherwise
    """
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "DS record hash algorithm"
        self.description = "Test the DS for missing or outdated hash algorithms"

    def do_we_have_what_we_need(self):
        if not self.broker.have_completed('DS'):
            return False
        if not self.broker.have_completed('DNSKEY'):
            return False
        return True

    def run_test(self):
        if self.broker.is_nxdomain('DS'):
            self.result_type = RESULTTYPE_BAD
            self.shortcircuit = TESTRESULTTYPE_TRUSTISSUE
            self.result_messages.append("No DS records for %s. This probably means that this domain is an island of security and we can not actually verify it"%self.broker.domain)
            return

        restype = None

        dsrecs = self.broker.get_records('DS')
        dnskeys = self.broker.get_records('DNSKEY')
        dnskeytags = set([key['i_key_tag'] for key in dnskeys])
        dskeytags = set([ds['key_tag'] for ds in dsrecs])

        checkdskeytags = [tag for tag in  dnskeytags if tag in dskeytags]

        for ktag in checkdskeytags:
            have_type2=False
            matching_ds = [ds for ds in dsrecs if ds['key_tag']==ktag]
            # we assume that the same key tag is only used by one DNSKEY. if there are multiple, the domain is proably broken anyway
            dnskey = [key for key in dnskeys if key['i_key_tag']==ktag][0]
            calculated_ds = dnskey['i_calculated_ds']
            for dsrec in matching_ds:
                actual_hash = dsrec['i_digeststr']
                actual_algo = dsrec['digest_type']
                if actual_algo == 2:
                    have_type2 = True
                if actual_algo not in calculated_ds:
                    self.result_messages.append("Unsupported ds hash algorithm %s in key tag %s"%(actual_algo,ktag))
                    self.result_type = RESULTTYPE_BAD
                    return
                if calculated_ds[actual_algo]!=actual_hash:
                    self.result_messages.append("DS Hash mismatch in key tag %s.calculated hash=%s, DS hash=%s , " % (ktag,calculated_ds[actual_algo],actual_hash))
                    self.result_type = RESULTTYPE_BAD
                    return

            if not have_type2:
                self.result_type = RESULTTYPE_BAD
                self.result_messages.append("DS hash type 2 missing in key tag %s"%ktag)
                return

        self.result_type = RESULTTYPE_GOOD
all_tests.append(DSDigestAlgo)

class RRSIGTimes(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Signature validity timing"
        self.description = "Test if the RRSIGs are expired (or close to expiration) or the validation could break due to clock skew"


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed('SOA'):
            return False
        return True

    def run_test(self):
        now=int(time.time())
        clock_skew_offset=3600
        # signatures should be refreshed within validity_ratio %
        # of the validity period
        validity_ratio = 0.7
        # signatures valid for more days have a risk for replay-attacks
        maximum_days = 90

        problem = False
        warning = False

        # TODO: Only check RRSIG from DNSKEY which are part of the trust chain
        for rdtype,val in self.broker.domaininfo['LOCAL_DNSSEC'].iteritems():
            if 'RRSIG' not in val:
                continue
            for rrsig in val['RRSIG']:
                inception = rrsig['inception']
                expiration = rrsig['expiration']
                ttl = rrsig['original_ttl']

                # check if validity period has started
                if inception>now:
                    problem = True
                    self.result_messages.append("RRSIG for %s key tag %s is not yet valid"%(rdtype,rrsig['key_tag']))
                # check if inception time accounts for clock skew offset
                if abs(inception-now)<clock_skew_offset:
                    problem = True
                    self.result_messages.append(
                        "RRSIG inception for %s key tag %s less than one hour from now - clock skew on resolvers will cause validation failure" % (rdtype, rrsig['key_tag']))

                expiration = rrsig['expiration']
                # check if expiration time expired
                if expiration<now:
                    problem = True
                    self.result_messages.append(
                        "RRSIG for %s key tag %s has expired!" % (rdtype, rrsig['key_tag']))

                # abort if problems exists
                if problem:
                    self.result_type = RESULTTYPE_BAD
                    return

                # check if remaining validity period is long enough
                validity_period = int(expiration-inception)
                if int(validity_ratio*validity_period)+inception < now:
                    warning = True
                    self.result_messages.append(
                    "RRSIG for %s key tag %s is dangerously close to expiration, resign the zone!" % (rdtype, rrsig['key_tag']))
                # check expiration time for replay-attack risk
                # https://tools.ietf.org/html/rfc6781#section-4.4.2.1
                time_until_expiration = expiration-now
                days_until_expiration = int(time_until_expiration / (23*3600))
                if days_until_expiration > maximum_days:
                    warning = True
                    self.result_messages.append(
                    "RRSIG expiration for %s key tag %s is long into the future, risk of replay attack!" % (rdtype, rrsig['key_tag']))
                # check if time until expiration is greater than TTL.
                # Assures that forwarding resolvers can validate signature too
                # https://tools.ietf.org/html/rfc6781#section-4.4.1
                if time_until_expiration < ttl:
                    warning = True
                    self.result_messages.append(
                    "RRSIG expiration for %s key tag %s is before remaining time of TTL, forwarding resolvers may not be able to validate RRSIG" % (rdtype, rrsig['key_tag']))

        if problem:
            self.result_type = RESULTTYPE_BAD
        elif warning:
            self.result_type = RESULTTYPE_WARNING
        else:
            self.result_type = RESULTTYPE_GOOD
all_tests.append(RRSIGTimes)

class RRSIGForEachDSAlgorithm(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "RFC compliance: DNSKEY RRSIG"
        self.description = "Is there an RRSIG in DNSKEY for every algorithm that is used in DS."


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed('DS') or not self.broker.have_completed('DNSKEY'):
            return False
        return True

    def run_test(self):
        ds_algorithms = set()
        for record in self.broker.get_records('DS'):
            ds_algorithms.add(record['algorithm'])

        rrsig_algorithms = set()
        for record in self.broker.get_rrsigs('DNSKEY'):
            rrsig_algorithms.add(record['algorithm'])

        diff = ds_algorithms - rrsig_algorithms
        if len(diff) >= 1:
            self.result_type = RESULTTYPE_BAD
            self.result_messages.append("An RRSIG in DNSKEY is missing for %d algorithms!", len(diff))
        else:
            self.result_type = RESULTTYPE_GOOD
all_tests.append(RRSIGForEachDSAlgorithm)

class DanglingDS(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Dangling DS"
        self.description = "Check for DS records without matching DNSKEY"


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("DS") or not self.broker.have_completed("DNSKEY"):
            return False
        return True

    def run_test(self):
        ds_key_tags = set()
        for record in self.broker.get_records("DS"):
            ds_key_tags.add(record["key_tag"])

        dnskey_key_tags = set()
        for record in self.broker.get_records("DNSKEY"):
            dnskey_key_tags.add(record["i_key_tag"])

        diff = ds_key_tags - dnskey_key_tags
        if len(diff) >= 1:
            self.result_type = RESULTTYPE_NEUTRAL
            self.result_messages.append("Dangling DS record(s) for missing key tag(s) %s"% " ".join([str(tag) for tag in diff]))
        else:
            self.result_type = RESULTTYPE_GOOD
all_tests.append(DanglingDS)

class NumberOfDNSKEYs(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "DNSKEYs RRSET size"
        self.description = "More than three DNSKEYs (1xKSK, 1xZSK, 1xRollover Key) are usually not needed. Additional keys increase the amplification factor in DOS attacks"


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("DNSKEY"):
            return False
        return True

    def run_test(self):
        dnskeys = self.broker.get_records("DNSKEY")
        ksks = [k for k in dnskeys if k['flags'] & 1 == 1]
        zsks = [k for k in dnskeys if k['flags'] & 1 == 0]

        self.result_messages.append("found %s DNSKEYS (%s KSK / %s ZSK)"%(len(dnskeys),len(ksks),len(zsks)))
        if len(dnskeys) > 3:
            self.result_type = RESULTTYPE_BAD
            self.result_messages.append("Too many DNSKEYs present. Not more than three are needed (zone signing key, key signing key and a rollover key).")
        else:
            self.result_type = RESULTTYPE_GOOD
all_tests.append(NumberOfDNSKEYs)

class KeyType(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.expected_keyalgo = 13
        self.expected_keyalgo_text = "ECDSAP256SHA256" # doesnt work, bug in dnspython? algorithm_to_text(self.expected_keyalgo)
        self.name = "Key strength"
        self.description = "The current best practice is to use %s keys."% self.expected_keyalgo_text


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("DNSKEY"):
            return False
        return True

    def run_test(self):
        dnskeys = self.broker.get_records("DNSKEY")
        self.result_type = RESULTTYPE_GOOD

        badalgos={}

        for key in dnskeys:
            tag = key.get('i_key_tag')
            algo = key['algorithm']
            if algo!=self.expected_keyalgo:
                if algo not in badalgos:
                    badalgos[algo]=[]
                badalgos[algo].append(tag)

        for algo,keytags in badalgos.iteritems():

            algo_text = algorithm_to_text(algo)
            if algo_text!=str(algo):
                algo_text="%s(%s)"%(algo_text,algo)

            self.result_type = RESULTTYPE_BAD
            self.result_messages.append("key tag %s using algorithm %s "%(" ".join(str(x) for x in keytags), algo_text))

        if self.result_type == RESULTTYPE_GOOD:
            self.result_messages.append("all keys are using "+self.expected_keyalgo_text)
        else:
            self.result_messages.append("we recommend upgrading to %s(%s)" %( self.expected_keyalgo_text,self.expected_keyalgo))
all_tests.append(KeyType)

class SEPFlag(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "SEP Flag (KSK vs ZSK)"
        self.description = "Checks if DS only point to KSKs (SEP flag set), check if the DNSKEY RRSET is only signed by KSKs"

    def do_we_have_what_we_need(self):
        return self.broker.have_completed("DNSKEY") and self.broker.have_completed("DS")

    def run_test(self):
        dnskeys = self.broker.get_records("DNSKEY")
        ksks = [k for k in dnskeys if k['flags'] & 1 == 1]
        zsks = [k for k in dnskeys if k['flags'] & 1 == 0]

        zsk_key_tags = set([k['i_key_tag'] for k in zsks])

        ds_key_tags = set()
        for record in self.broker.get_records("DS"):
            ds_key_tags.add(record["key_tag"])

        self.result_type = RESULTTYPE_GOOD

        if len(ksks)<1:
            self.result_type = RESULTTYPE_BAD
            self.result_messages.append(
                "No KSKs in the DNSKEY RRSET")

        for key_tag in ds_key_tags:
            if key_tag in zsk_key_tags:
                self.result_type = RESULTTYPE_BAD
                self.result_messages.append("DS record points to a key tag %s which does not have the SEP flag set (ZSK instead of KSK)"%key_tag)

        for record in self.broker.get_rrsigs('DNSKEY'):
            key_tag = record['key_tag']
            if key_tag in zsk_key_tags:
                self.result_type = RESULTTYPE_BAD
                self.result_messages.append(
                    "DNSKEY rrset is signed with key tag %s which does not have the SEP flag set (ZSK instead of KSK)"%key_tag)


all_tests.append(SEPFlag)

class NSEC3HashAlgo(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "NSEC3 hash algorithm"
        self.description = "Only hash algorithm 1 is currently allowed in NSEC3"


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("NSEC3"):
            return False
        return True

    def run_test(self):
        self.result_type = RESULTTYPE_GOOD

        nsec3recs = self.broker.get_records('NSEC3')
        if len(nsec3recs)==0:
            self.result_messages.append("NSEC3 not in use")
            return

        for nsecp in nsec3recs:
            alg=nsecp["algorithm"]
            if alg!=1:
                self.result_type= RESULTTYPE_BAD
                self.result_messages.append("NSEC3 hash algorithm is %s instead of 1"%alg)
                return
all_tests.append(NSEC3HashAlgo)

class NSEC3PARAMOptOut(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "NSEC3 Opt-out"
        self.description = "NSEC3 Opt-out should only be used in large domains with many delegations (TLDs etc)"

    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("NSEC3"):
            return False
        return True

    def run_test(self):

        nsec3recs = self.broker.get_records('NSEC3')
        if len(nsec3recs)==0:
            self.result_type = RESULTTYPE_GOOD
            self.result_messages.append("NSEC3 not in use")
            return


        for nsec3 in nsec3recs:
            if nsec3['flags'] & 1:
                self.result_type = RESULTTYPE_BAD
                self.result_messages.append("NSEC3 opt-out is set")
                return

            if nsec3['flags'] != 0:
                self.result_type = RESULTTYPE_BAD
                self.result_messages.append("NSEC3 unused flags are set")
                return

        self.result_type = RESULTTYPE_GOOD
all_tests.append(NSEC3PARAMOptOut)

# Console mode


class FunkyConsole(object):

    def __init__(self):
        self.BG = {}
        self.BG["black"] = "40"
        self.BG["red"] = "41"
        self.BG["green"] = "4"
        self.BG["brown"] = "43"
        self.BG["blue"] = "44"
        self.BG["magenta"] = "45"
        self.BG["cyan"] = "46"
        self.BG["white"] = "47"

        self.RESET = "\x1b[0m"

        self.MODE = {}
        self.MODE["default"] = "0"
        self.MODE["bold"] = "1"
        self.MODE["blink"] = "5"
        self.MODE["noblink"] = "25"

        self.FG = {}
        self.FG["white"] = "00"
        self.FG["black"] = "30"
        self.FG["red"] = "31"
        self.FG["green"] = "32"
        self.FG["brown"] = "33"
        self.FG["blue"] = "34"
        self.FG["magenta"] = "35"
        self.FG["cyan"] = "36"
        self.FG["gray"] = "37"
        # shortcuts
        self.FG["yellow"] = self.FG["brown"] + ";" + self.MODE["bold"]

    def strcolor(self, content, commandlist, resetAfter=True):
        """returns the content encapsulated in the escapesequences to print coloured output"""
        if type(commandlist) is str:
            commandlist = (self.FG[commandlist],)
        esc = self._buildescape(commandlist)
        ret = esc + str(content)
        if resetAfter:
            ret = ret + self.RESET
        return ret

    def _buildescape(self, commandlist):
        """builds escape sequences"""
        escseq = "\x1b["
        for cmd in commandlist:
            if cmd != None:
                escseq = escseq + cmd + ";"
        escseq = escseq[0:-1]  # strip last ;
        escseq = escseq + "m"
        return escseq


def main():
    domain = sys.argv[1] # TODO: argparse, resolver ...
    broker = DNSInfoBroker(domain)
    console = FunkyConsole()
    for testclass in all_tests:
        testinstance = testclass(broker)
        name = testinstance.name
        description = testinstance.description



        print(console.strcolor(name,[console.MODE["bold"],]))
        print(console.strcolor("-"*len(name),[console.MODE["bold"],]))
        print(description)

        if not testinstance.do_we_have_what_we_need():
            print("Test %s skipped - missing info" % testinstance.name)
            continue

        testinstance.run_test()

        rtype = testinstance.result_type
        if rtype == RESULTTYPE_GOOD:
            print(console.strcolor('OK', [console.MODE['bold'],console.FG['green']]))
        elif rtype== RESULTTYPE_BAD:
            print(console.strcolor('BAD',[console.MODE['bold'],console.FG['red']]))
        elif rtype == RESULTTYPE_WARNING:
            print(console.strcolor('WARNING', 'yellow'))
        else:
            print(console.strcolor('UNKNOWN', 'gray'))

        for message in testinstance.result_messages:
            print("* %s"%message)

        # abort tests
        if testinstance.shortcircuit != None:
            break


        print()

