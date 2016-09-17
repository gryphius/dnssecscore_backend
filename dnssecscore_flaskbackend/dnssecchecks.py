NXDOMAIN = None


RESULTTYPE_UNKNOWN = "unknown"
RESULTTYPE_GOOD = "good"
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
        self._load_info()
        self.domain = domain

    def _load_info(self):
        pass

    def have_completed(self, rtype):
        return rtype in self.domaininfo

    def is_nxdomain(self, rtype): #or empty
        return self.domaininfo[rtype] == NXDOMAIN

    def get_records(self, rtype):
        return self.domaininfo[rtype]

class TestBase(object):
    def __init__(self,broker):
        self.name="test name"
        self.description="test description"
        self.broker = broker
        self.resulttype = RESULTTYPE_UNKNOWN

        self.shortcircuit = None # set a TESTRESULTTYPE_... to abort all tests

        self.result_weight = 1 # how important is this test. 0 for "informative only"
        self.result_messages = []



    def do_we_have_what_we_need(self):
        #ask the broker if the records have been completed
        return False

    def run_test(self):
        pass


class DummyInfo(TestBase):
    def do_we_have_what_we_need(self):
        return True

    def run_test(self):
        self.resulttype = RESULTTYPE_NEUTRAL
        self.result_weight  = 0
        self.result_messages = ["This is just a dummy info message to see if things are working. ", ]


class DummyGood(TestBase):
    def do_we_have_what_we_need(self):
        return True

    def run_test(self):
        self.resulttype = RESULTTYPE_GOOD
        self.result_weight  = 1
        self.result_messages = ["This is just a dummy success result. That mean's you've passed... YAY!", ]

class DummyBad(TestBase):
    def do_we_have_what_we_need(self):
        return True

    def run_test(self):
        self.resulttype = RESULTTYPE_BAAD
        self.result_weight  = 1
        self.result_messages = ["This is just a dummy fail result. Sorry to say you've failed this one... BOOOH!", ]


class CheckAreWeSigned(TestBase):
    def __init__(self, broker):
        super(TestBase, self).__init__(broker)



all_tests=[DummyInfo, DummyGood, DummyBad ]
