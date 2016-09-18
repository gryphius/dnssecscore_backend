import dns.resolver
import pprint
import time
from dns.dnssec import algorithm_to_text

from dns.resolver import NoAnswer

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

ADS_BACKEND_AVAILABLE=False # check if our cool dnslookup to dict function is ready
USE_ADS_BACKEND_IF_POSSIBLE = True
try:
    from all_the_shiet import all_the_shiet as do_all_lookups
    ADS_BACKEND_AVAILABLE = True
except Exception,e:
    print "Could not load ads backend: %s"%str(e)
    pass

class DNSInfoBroker(object):
    def __init__(self, domain):
        self.domaininfo={}
        self.domain = domain

        self._load_info()

    def _load_info(self):


        if ADS_BACKEND_AVAILABLE and USE_ADS_BACKEND_IF_POSSIBLE:
            print "Running DNS lookup using ADS Backend"
            self.domaininfo = do_all_lookups(self.domain)
        else:
            print "Running DNS lookup using our own dummy"
            self.load_single_record('DS')
            self.load_single_record('DNSKEY')
            self.load_single_record('SOA')
        print pprint.pformat(self.domaininfo)


    def have_completed(self, rtype):
        return rtype.upper() in self.domaininfo

    def is_nxdomain(self, rtype): #or empty
        return self.domaininfo[rtype.upper()] in ( None, {} )

    def get_records(self, rtype):
        return self.domaininfo[rtype.upper()]['RR']

    def get_rrsigs(self, rtype):
        return self.domaininfo[rtype.upper()]['RRSIG']


    def load_single_record(self, rtype):
        rtype = rtype.upper()

        try:
            answers = dns.resolver.query(self.domain, rtype)
        except NoAnswer:
            self.domaininfo[rtype]=NXDOMAIN
            return

        newinfo = []

        for rdata in answers:
            d = dict()
            d['text'] = rdata.to_text()
            newinfo.append(d)

            if rtype=='DNSKEY':
                d['flags']=rdata.flags

        self.domaininfo[rtype]= {'RR' : newinfo }


class TestBase(object):
    def __init__(self,broker):
        self.name="dummy test name"
        self.description="test description"
        self.broker = broker

        self.shortcircuit = None # set a TESTRESULTTYPE_... to abort all tests

        self.result_type = RESULTTYPE_UNKNOWN
        self.result_weight = 1 # how important is this test. 0 for "informative only"
        self.result_messages = []

    def do_we_have_what_we_need(self):
        #ask the broker if the records have been completed
        return False

    def run_test(self):
        pass


class DummyInfo(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Important information"
        self.description = "This block well tell you something really informative"
        self.result_weight = 0

    def do_we_have_what_we_need(self):
        return True

    def run_test(self):
        self.result_type = RESULTTYPE_NEUTRAL
        self.result_messages = ["This is just a dummy info message to see if things are working. ", ]


class DummyGood(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Successful test dummy"
        self.description = "This test always succeeds - how nice!"

    def do_we_have_what_we_need(self):
        return True

    def run_test(self):
        self.result_type = RESULTTYPE_GOOD
        self.result_weight  = 1
        self.result_messages = ["This is just a dummy success result. That mean's you've passed... YAY!", ]

class DummyBad(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Failed test dummy"
        self.description = "This test always fails - and there is NOTHING you can do about it..muahahaha"

    def do_we_have_what_we_need(self):
        return True

    def run_test(self):
        self.result_type = RESULTTYPE_BAD
        self.result_weight  = 1
        self.result_messages = ["This is just a dummy fail result. Sorry to say you've failed this one... BOOOH!", ]


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

        dnskeys = self.broker.get_records('DNSKEY')


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

        ds = self.broker.get_records('DS')
        numds = len(ds)
        self.result_messages.append("found %s DS records" % numds)
        if numds>2:
            self.result_messages.append("More than two DS records are pointless")
            self.result_weight = 0.8
            self.result_type = RESULTTYPE_WARNING
            return

        self.result_type = RESULTTYPE_GOOD

class DSDigestAlgo(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "DS record hash algorithm"
        self.description = "Test the DS for missing or outdated hash algorithms"

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

        restype = None

        dsrecs = self.broker.get_records('DS')

        have_typetwo = False
        for ds in dsrecs:
            digest_type = ds.get('digest_type')
            if digest_type == 1:
                restype = RESULTTYPE_BAD
                self.result_messages.append('There is a DS record with insecure hash type 1')

            if digest_type == 2:
                have_typetwo = True

        if not have_typetwo:
            restype = RESULTTYPE_BAD
            self.result_messages.append("DS hash type 2 must be available, but it isn't")

        if restype==None:
            restype = RESULTTYPE_GOOD

        self.result_type = restype

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
        minimum_days_left = 5

        problem = False
        warning = False

        all_inceptions=[]
        all_expirations=[]

        for rdtype,val in self.broker.domaininfo.iteritems():
            if 'RRSIG' not in val:
                continue

            for rrsig in val['RRSIG']:
                inception = rrsig['inception']
                all_inceptions.append(inception)
                if inception>now:
                    problem = True
                    self.result_messages.append("RRSIG for %s key tag %s is not yet valid"%(rdtype,rrsig['key_tag'])) #

                if abs(inception-now)<clock_skew_offset:
                    warning = True
                    self.result_messages.append(
                        "RRSIG for %s key tag %s is dangerously close to now - clock skew on resolvers will cause validation failure" % (rdtype, rrsig['key_tag']))  #

                expiration = rrsig['expiration']
                all_expirations.append(expiration)
                if expiration<now:
                    problem = True
                    self.result_messages.append(
                        "RRSIG for %s key tag %s has expired!" % (rdtype, rrsig['key_tag']))  #

        days_until_expiration = max(0,int((min(all_expirations)-now) / (24*3600)))
        self.result_messages.append(
            "RRSIG will expire in %s days" % (days_until_expiration) ) #

        if days_until_expiration < minimum_days_left:
            warning = True
            self.result_messages.append(
            "RRSIG are dangerously close to expiration, resign the zone!" )


        if problem:
            self.result_type = RESULTTYPE_BAD
        elif warning:
            self.result_type = RESULTTYPE_WARNING
        else:
            self.result_type = RESULTTYPE_GOOD

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

class DanglingDS(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Check if there are the same key tags in DS and DNSKEY."
        self.description = "This test will test if the same key tags exist in both DS record an the DNSKEYs."


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
            dnskey_key_tags.add(record["key_tag"])

        diff = ds_key_tags - dnskey_key_tags
        if len(diff) >= 1:
            self.result_type = RESULTTYPE_NEUTRAL
            self.result_messages.append("There exists a dangling key tag %s in the DS record.", diff)
        else:
            self.result_type = RESULTTYPE_GOOD

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

class KeyType(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.expected_keyalgo = 13
        self.expected_keyalgo_text = "ECDSAP256SHA256" # doesnt work, bug in dnspython? algorithm_to_text(self.expected_keyalgo)
        self.name = "Key Type"
        self.description = "The current best practice is to use %s keys."% self.expected_keyalgo_text


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("DNSKEY"):
            return False
        return True

    def run_test(self):
        dnskeys = self.broker.get_records("DNSKEY")
        self.result_type = RESULTTYPE_GOOD
        for key in dnskeys:
            tag = key.get('key_tag')
            algo = key['algorithm']
            algo_text = algorithm_to_text(algo)
            if algo_text!=str(algo):
                algo_text="%s(%s)"%(algo_text,algo)
            if  algo!= self.expected_keyalgo:
                self.result_type = RESULTTYPE_BAD
                self.result_messages.append("Your key tag %s is using algorithm %s instead of %s(%s)"%(tag, algo_text,self.expected_keyalgo_text,self.expected_keyalgo))


class NSEC3HashAlgo(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "NSEC3 hash algorithm"
        self.description = "Only hash algorithm 1 is currently allowed in NSEC3"


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("NSEC3PARAM"):
            return False
        return True

    def run_test(self):
        self.result_type = RESULTTYPE_GOOD
        if self.broker.is_nxdomain('NSEC3PARAM'):
            self.result_messages.append("NSEC3 not in use")
            return

        for nsecp in self.broker.get_records('NSEC3PARAM'):
            alg=nsecp["algorithm"]
            if alg!=1:
                self.result_type= RESULTTYPE_BAD
                self.result_messages.append("NSEC3 hash algorithm is %s instead of 1"%alg)
                return

class NSEC3PARAMOptOut(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "NSEC3 Opt-out"
        self.description = "NSEC3 Opt-out should only be used in large domains with many delegations (TLDs etc)"

    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("NSEC3PARAM"):
            return False
        return True

    def run_test(self):
        if self.broker.is_nxdomain('NSEC3PARAM'):
            self.result_type = RESULTTYPE_GOOD
            self.result_messages.append("NSEC3 is not in use.")
            return

        nsec3param = self.broker.get_records("NSEC3PARAM")

        if nsec3param[0].flags & 1:
            self.result_type = RESULTTYPE_BAD
            self.result_messages.append("NSEC3PARAM opt out is enabled, but shouldn't be.")
            return

        if nsec3param[0].flags != 0:
            self.result_type = RESULTTYPE_BAD
            self.result_messages.append("NSEC3PARAM unused flags are set, but shouldn't be.")
            return

        self.result_type = RESULTTYPE_GOOD





all_tests=[AreWeSigned, HaveDS, DSDigestAlgo, RRSIGTimes,
RRSIGForEachDSAlgorithm, DanglingDS, NumberOfDNSKEYs, KeyType, NSEC3HashAlgo, NSEC3PARAMOptOut
]

# Dummies we can use for testing DummyInfo, DummyGood, DummyBad,]
