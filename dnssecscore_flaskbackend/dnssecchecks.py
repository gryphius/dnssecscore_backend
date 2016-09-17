import dns.resolver

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


class DNSInfoBroker(object):
    def __init__(self, domain):
        self.domaininfo={}
        self.domain = domain

        self._load_info()

    def _load_info(self):
        self.load_single_record('DS')
        self.load_single_record('DNSKEY')
        self.load_single_record('SOA')

        print self.domaininfo
        print self.have_completed('DNSKEY')


    def have_completed(self, rtype):
        return rtype.upper() in self.domaininfo

    def is_nxdomain(self, rtype): #or empty
        return self.domaininfo[rtype.upper()] == NXDOMAIN

    def get_records(self, rtype):
        return self.domaininfo[rtype.upper()]

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

        self.domaininfo[rtype] = newinfo


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






all_tests=[AreWeSigned, HaveDS,

    DummyInfo, DummyGood, DummyBad,
            ]
