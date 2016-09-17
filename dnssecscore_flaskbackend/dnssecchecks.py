import dns.resolver
import pprint
import time

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
        self.name = "Is the domain protected with DNSSEC"
        self.description = "Basic test to see if the domain publishes DNSKEY records"

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
        self.result_messages.append("found %s DNSKEYS (x ZSK/y KSK)"%len(dnskeys))


class HaveDS(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Check DS records"
        self.description = "Check if we can validate this domain starting from the root or if this an island of security. "

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
        self.name = "Check DS records algorithm"
        self.description = "This test checks the DS hash algorithms used. SHA1 is discouraged, SHA2 must be available, optionally 3 and 4"

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
        self.name = "Check RRSIG inception and expiration times"
        self.description = "This test will test if your RRSIGs are close to expiration or the inception could be affected by clock skew"


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed('SOA'):
            return False
        return True

    def run_test(self):
        now=int(time.time())
        clock_skew_offset=3600
        minimum_days_left = 5

        problem = False

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
                    problem = True
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
            problem = True
            self.result_messages.append(
            "RRSIG are dangerously close to expiration, resign the zone!" )


        if problem:
            self.result_type = RESULTTYPE_BAD
        else:
            self.result_type = RESULTTYPE_GOOD

class RRSIGForEachDSAlgorithm(TestBase):
    def __init__(self, broker):
        TestBase.__init__(self, broker)
        self.name = "Check if there is an RRSIG in DNSKEY for each algorithm in DS."
        self.description = "This test will test if there exists an RRSIG in DNSKEY for every algorithm that is used in DS."


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
        self.name = "Check if there are too many DNSKEYs."
        self.description = "This test will test if the domain has more than three DNSKEYs (three is plenty)."


    def do_we_have_what_we_need(self):
        if not self.broker.have_completed("DNSKEY"):
            return False
        return True

    def run_test(self):
        if len(self.broker.get_records("DNSKEY")) > 3:
            self.result_type = RESULTTYPE_BAD
            self.result_messages.append("Too many DNSKEYs present. Not more than three are needed (zone signing key, key signing key and a rollover key).")
        else:
            self.result_type = RESULTTYPE_GOOD

all_tests=[AreWeSigned, HaveDS, DSDigestAlgo, RRSIGTimes,
RRSIGForEachDSAlgorithm, DanglingDS, NumberOfDNSKEYs,
]

# Dummies we can use for testing DummyInfo, DummyGood, DummyBad,]
