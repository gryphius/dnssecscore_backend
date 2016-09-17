import dns.name
import dns.message
import dns.query
import dns.flags
import base64
import time
import pprint
import multiprocessing.pool

def dnskey_shiet(domain, dns_server = "8.8.8.8", output = False):
    dnskey_request = dns.message.make_query(domain, dns.rdatatype.DNSKEY)
    dnskey_request.want_dnssec()
    dnskey_answers = dns.query.udp(dnskey_request, dns_server).answer

    if output:
        print "DNSKEY"
        print "============================"
    response = dict()
    if len(dnskey_answers) >= 1:
        response['RR'] = []
        for rdata in dnskey_answers[0]:
            response['RR'].append({
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
        response['RRSIG'] = []
        for rdata in dnskey_answers[1]:
            response['RRSIG'].append({
                "algorithm" : rdata.algorithm,
                "inception" : rdata.inception,
                "key_tag" : rdata.key_tag,
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

    return response

def soa_shiet(domain, dns_server = "8.8.8.8", output = False):
    soa_request = dns.message.make_query(domain, dns.rdatatype.SOA)
    soa_request.want_dnssec()
    soa_answers = dns.query.udp(soa_request, dns_server).answer

    if output:
        print "SOA"
        print "============================"
    response = dict()
    if len(soa_answers) >= 1:
        response['RR'] = []
        for rdata in soa_answers[0]:
            response['RR'].append({
                "expire" : rdata.expire,
                "ttl" : soa_answers[0].ttl
            })
            if output:
                print "  Expire: ", rdata.expire
                print "  TTL: ", soa_answers[0].ttl
                print "----------------------------"
    if len(soa_answers) >= 2:
        response['RRSIG'] = []
        for rdata in soa_answers[1]:
            response['RRSIG'].append({
                "algorithm" : rdata.algorithm,
                "inception" : rdata.inception,
                "key_tag" : rdata.key_tag,
                "expiration" : rdata.expiration,
                "ttl" : soa_answers[1].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Inception: ", rdata.inception
                print "  Key tag: ", rdata.key_tag
                print "  Expiration: ", rdata.expiration
                print "  TTL: ", soa_answers[1].ttl
                print "----------------------------"

    return response

def ds_shiet(domain, dns_server = "8.8.8.8", output = False):
    ds_request = dns.message.make_query(domain, dns.rdatatype.DS)
    ds_request.want_dnssec()
    ds_answers = dns.query.udp(ds_request, dns_server).answer

    if output:
        print "DS"
        print "============================"
    response = dict()
    if len(ds_answers) >= 1:
        response['RR'] = []
        for rdata in ds_answers[0]:
            response['RR'].append({
                "algorithm" : rdata.algorithm,
                "digest_type" : rdata.digest_type,
                "key_tag" : rdata.key_tag,
                "ttl" : ds_answers[0].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Digest type: ", rdata.digest_type
                print "  Key tag: ", rdata.key_tag
                print "  TTL: ", ds_answers[0].ttl
                print "----------------------------"
    if len(ds_answers) >= 2:
        response['RRSIG'] = []
        for rdata in ds_answers[1]:
            response['RRSIG'].append({
                "algorithm" : rdata.algorithm,
                "inception" : rdata.inception,
                "key_tag" : rdata.key_tag,
                "expiration" : rdata.expiration,
                "ttl" : ds_answers[1].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Inception: ", rdata.inception
                print "  Key tag: ", rdata.key_tag
                print "  Expiration: ", rdata.expiration
                print "  TTL: ", ds_answers[1].ttl
                print "----------------------------"

    return response



def all_the_shiet(domain, dns_server = "8.8.8.8", output = False):
    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    pool = multiprocessing.pool.ThreadPool(processes=1)
    dnskey_result = pool.apply_async(dnskey_shiet, (domain, dns_server, output))
    soa_result = pool.apply_async(soa_shiet, (domain, dns_server, output))
    ds_result = pool.apply_async(ds_shiet, (domain, dns_server, output))

    response = dict()
    response['DNSKEY'] = dnskey_result.get()
    response['SOA'] = soa_result.get()
    response['DS'] = ds_result.get()

    if output:
        pprint.pprint(response)

    return response
