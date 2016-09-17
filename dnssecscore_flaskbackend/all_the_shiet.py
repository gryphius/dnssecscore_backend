import dns.name
import dns.message
import dns.query
import dns.flags
import base64
import time
import pprint

def all_the_shiet(domain, dns_server = "8.8.8.8", output = False):

    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    # DNSKEY SOA DS RRSIG
    # dnskey, algorithm, flags, protocol, ttl
    # soa, expiry, ttl
    # ds, digest type, algorithm, keytag, ttl
    # rrsig, algorithm, start time, end time, key tag, ttl
    # RRSIG
    dnskey_request = dns.message.make_query(domain, dns.rdatatype.DNSKEY)
    dnskey_request.want_dnssec()
    soa_request = dns.message.make_query(domain, dns.rdatatype.SOA)
    soa_request.want_dnssec()
    ds_request = dns.message.make_query(domain, dns.rdatatype.DS)
    ds_request.want_dnssec()

    dnskey_answers = dns.query.udp(dnskey_request, dns_server).answer
    soa_answers = dns.query.udp(soa_request, dns_server).answer
    ds_answers = dns.query.udp(ds_request, dns_server).answer

    response = dict()
    response['DNSKEY'] = dict()
    response['SOA'] = dict()
    response['DS'] = dict()

    if output:
        print "DNSKEY:"
        print "============================"
    if len(dnskey_answers) >= 1:
        response['DNSKEY']['RR'] = []
        for rdata in dnskey_answers[0]:
            response['DNSKEY']['RR'].append({
                "algorithm" : rdata.algorithm,
                "flags" : rdata.flags,
                "key" : base64.b64encode(rdata.key),
                "protocol" : rdata.protocol,
                "ttl" : dnskey_answers[0].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Flags: ", rdata.flags
                print "  Key: ", base64.b64encode(rdata.key)
                print "  Protocol: ", rdata.protocol
                print "  TTL: ", dnskey_answers[0].ttl
                print "----------------------------"
    if len(dnskey_answers) >= 2:
        response['DNSKEY']['RRSIG'] = []
        for rdata in dnskey_answers[1]:
            response['DNSKEY']['RRSIG'].append({
                "algorithm" : rdata.algorithm,
                "inception" : rdata.inception,
                "key_gat" : rdata.key_tag,
                "expiration" : rdata.expiration,
                "ttl" : dnskey_answers[1].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Inception: ", rdata.inception
                print "  Key tag: ", rdata.key_tag
                print "  Expiration: ", rdata.expiration
                print "  TTL: ", dnskey_answers[1].ttl
                print "----------------------------"

    if output:
        print "SOA:"
        print "============================"
    if len(soa_answers) >= 1:
        response['SOA']['RR'] = []
        for rdata in soa_answers[0]:
            response['SOA']['RR'].append({
                "expire" : rdata.expire,
                "ttl" : dnskey_answers[0].ttl
            })
            if output:
                print "  Expire: ", rdata.expire
                print "  TTL: ", soa_answers[0].ttl
                print "----------------------------"
    if len(soa_answers) >= 2:
        response['SOA']['RRSIG'] = []
        for rdata in soa_answers[1]:
            response['SOA']['RRSIG'].append({
                "algorithm" : rdata.algorithm,
                "inception" : rdata.inception,
                "key_gat" : rdata.key_tag,
                "expiration" : rdata.expiration,
                "ttl" : dnskey_answers[1].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Inception: ", rdata.inception
                print "  Key tag: ", rdata.key_tag
                print "  Expiration: ", rdata.expiration
                print "  TTL: ", soa_answers[1].ttl
                print "----------------------------"

    if output:
        print "DS:"
        print "============"
    if len(ds_answers) >= 1:
        response['DS']['RR'] = []
        for rdata in ds_answers[0]:
            response['DS']['RR'].append({
                "algorithm" : rdata.algorithm,
                "digest_type" : rdata.digest_type,
                "key_tag" : rdata.key_tag,
                "ttl" : dnskey_answers[0].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Digest type: ", rdata.digest_type
                print "  Key tag: ", rdata.key_tag
                print "  TTL: ", ds_answers[0].ttl
                print "----------------------------"
    if len(ds_answers) >= 2:
        response['DS']['RRSIG'] = []
        for rdata in ds_answers[1]:
            response['DS']['RRSIG'].append({
                "algorithm" : rdata.algorithm,
                "inception" : rdata.inception,
                "key_gat" : rdata.key_tag,
                "expiration" : rdata.expiration,
                "ttl" : dnskey_answers[1].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Inception: ", rdata.inception
                print "  Key tag: ", rdata.key_tag
                print "  Expiration: ", rdata.expiration
                print "  TTL: ", ds_answers[1].ttl
                print "----------------------------"

    if output:
        pprint.pprint(response)

    return response
