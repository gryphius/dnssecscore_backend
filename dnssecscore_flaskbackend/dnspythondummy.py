#!/usr/bin/python2
import dns.resolver


if False:
    answers = dns.resolver.query('wgwh.ch.', 'DNSKEY')
    for rdata in answers:
        #print 'Host', rdata.exchange, 'has preference', rdata.preference
        #print dir(rdata)
        #print vars(rdata)
        vars = [i for i in dir(rdata) if not i.startswith('_')]
        print vars
        #print rdata.key
        print rdata.to_text()
        print rdata.protocol
        print rdata.algorithm


if False:
    answers = dns.resolver.query('wgwh.ch', 'ANY')
    for rdata in answers:
        # print 'Host', rdata.exchange, 'has preference', rdata.preference
        # print dir(rdata)
        # print vars(rdata)
        vars = [i for i in dir(rdata) if not i.startswith('_')]
        print vars

if True:
    import dns.name
    import dns.message
    import dns.query
    import dns.flags

    domain = 'wgwh.ch.'
    #name_server = '8.8.8.8'
    ADDITIONAL_RDCLASS = 65535

    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    request = dns.message.make_query(domain, dns.rdatatype.DNSKEY)
    request.want_dnssec()
    #request.flags |= dns.flags.AD
    #request.flags |= dns.flags.DO
    #request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
    #                 dns.rdatatype.OPT, create=True, force_unique=True)
    response = dns.query.udp(request, '8.8.8.8')
    #for rdata in response.answer:
    #    # print 'Host', rdata.exchange, 'has preference', rdata.preference
    #   # print dir(rdata)
    #   # print vars(rdata)
    #   vars = [i for i in dir(rdata) if not i.startswith('_')]
    #   print vars
    #   print rdata.to_text()
    response.answer.__class__
    for rrset in response.answer:
        print "NEW RRSET Starting..."
        for thing in rrset:
            print thing.__class__


    #print response.additional
    #print response.authority

if False:
    answers = dns.resolver.query('wgwh.ch', dns.rdatatype.RRSIG,
                            dns.rdataclass.IN,
                            raise_on_no_answer=False)
    print dir(answers)
    for rdata in answers.rrset:
        # print 'Host', rdata.exchange, 'has preference', rdata.preference
        # print dir(rdata)
        # print vars(rdata)
        vars = [i for i in dir(rdata) if not i.startswith('_')]
        print vars
        # print rdata.key
        print rdata.to_text()
        print rdata.protocol
        print rdata.algorithm

if False:
    answers = dns.resolver.query('dnssecscore.com.', 'RRSIG', raise_on_no_answer=False)
    print answers.answer
    print answers.additional
    print answers.authority
    for rdata in answers:
        #print 'Host', rdata.exchange, 'has preference', rdata.preference
        #print dir(rdata)
        #print vars(rdata)
        vars = [i for i in dir(rdata) if not i.startswith('_')]
        print vars
        #print rdata.key
        print rdata.to_text()
        print rdata.protocol
        print rdata.algorithm