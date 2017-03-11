#TODO: sys path to new checklib 

from nosetestdata import *
from dnsseccheck.dnssecchecks import DNSInfoBroker, AreWeSigned, RESULTTYPE_GOOD, RESULTTYPE_BAD, RESULTTYPE_NEUTRAL, RESULTTYPE_WARNING, TESTRESULTTYPE_INSECURE
from nose.tools import assert_equal
import copy

class TestAreWeSigned(object):
    def setUp(self):
        self.broker = DNSInfoBroker(domain=None)
        self.broker.domaininfo = copy.deepcopy(testdata_vmware)
        self.subject = AreWeSigned(self.broker)

    def test_positive(self):
        """Test if this test detects dnskeys """
        self.subject.run_test()
        assert_equal(self.subject.shortcircuit, None)
        assert_equal(self.subject.result_type, RESULTTYPE_GOOD )


    def test_negative(self):
        """If no DNSKEYS are present, the test should shortcircuit"""
        self.broker.domaininfo['LOCAL_DNSSEC']['DNSKEY']['DNSKEY']=None
        self.subject.run_test()
        assert_equal(self.subject.shortcircuit, TESTRESULTTYPE_INSECURE, "Domain with no DNSKEY should shortcircuit to INSECURE")
        assert_equal(self.subject.result_type, RESULTTYPE_BAD)




