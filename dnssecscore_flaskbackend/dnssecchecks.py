NXDOMAIN = None

class DNSInfoBroker(object):
    def __init__(self, domain):
        #TODO: load the domain info here
        self.domaininfo={}

    def have_completed(self, rtype):
        return rtype in self.domaininfo

    def is_nxdomain(self, rtype): #or empty
        return self.domaininfo[rtype] == NXDOMAIN

    def get_records(self, rtype):
        return self.domaininfo[rtype]

class CheckBase(object):
    def __init__(self,broker):
        self.name="test name"
        self.description="test description"
        self.broker = brokder

    def do_we_have_what_we_need(self):
        #ask the broker if the records have been completed
        return True


class CheckAreWeSigned(CheckBase):
    def __init__(self):
        pass


all_checks=[]
