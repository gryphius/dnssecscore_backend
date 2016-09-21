import dns.name
import dns.message
import dns.query
import dns.flags
import base64
import time
import pprint
import multiprocessing.pool
import struct
TIMEOUT = 3

def dnskey_shiet(domain, dns_server = "8.8.8.8", output = False):
    dnskey_request = dns.message.make_query(domain, dns.rdatatype.DNSKEY)
    dnskey_request.want_dnssec()
    dnskey_answers = dns.query.udp(dnskey_request, dns_server, timeout=TIMEOUT)
    if dnskey_answers.flags & dns.flags.TC:
        dnskey_answers = dns.query.tcp(dnskey_request, dns_server, timeout=TIMEOUT)
    dnskey_answers = dnskey_answers.answer

    if output:
        print "DNSKEY"
        print "============================"
    response = dict()
    if len(dnskey_answers) >= 1:
        response['RR'] = []
        for rdata in dnskey_answers[0]:
            b64key = base64.b64encode(rdata.key)
            response['RR'].append({
                "algorithm" : rdata.algorithm,
                "flags" : rdata.flags,
                "key" : b64key,
                "key_tag" : calc_keyid(rdata.flags, rdata.protocol, rdata.algorithm, b64key),
                "protocol" : rdata.protocol,
                "ttl" : dnskey_answers[0].ttl,
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Flags: ", rdata.flags
                print "  Key: ", base64.b64encode(rdata.key)
                print "  Key size: ", len(base64.b64encode(rdata.key)) * 64
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
    soa_answers = dns.query.udp(soa_request, dns_server, timeout=TIMEOUT)
    if soa_answers.flags & dns.flags.TC:
        soa_answers = dns.query.tcp(soa_request, dns_server, timeout=TIMEOUT)
    soa_answers = soa_answers.answer

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
    ds_answers = dns.query.udp(ds_request, dns_server, timeout=TIMEOUT)
    if ds_answers.flags & dns.flags.TC:
        ds_answers = dns.query.tcp(ds_request, dns_server, timeout=TIMEOUT)
    ds_answers = ds_answers.answer

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

def nsec3param_shiet(domain, dns_server = "8.8.8.8", output = False):
    nsec3param_request = dns.message.make_query(domain, dns.rdatatype.NSEC3PARAM)
    nsec3param_request.want_dnssec()
    nsec3param_answers = dns.query.udp(nsec3param_request, dns_server, timeout=TIMEOUT)
    if nsec3param_answers.flags & dns.flags.TC:
        nsec3param_answers = dns.query.tcp(nsec3param_request, dns_server, timeout=TIMEOUT)
    nsec3param_answers = nsec3param_answers.answer

    if output:
        print "NSEC3PARAM" #hash alg, num of iter, salt, ttl
        print "============================"
    response = dict()
    if len(nsec3param_answers) >= 1:
        response['RR'] = []
        for rdata in nsec3param_answers[0]:
            response['RR'].append({
                "algorithm" : rdata.algorithm,
                "iterations" : rdata.iterations,
                "flags" : rdata.flags,
                "salt" : rdata.salt,
                "ttl" : nsec3param_answers[0].ttl
            })
            if output:
                print dir(rdata)
                print "  Algorithm: ", rdata.algorithm
                print "  Iterations: ", rdata.iterations
                print "  Flags: ", rdata.flags
                print "  Salt: ", rdata.salt
                print "  TTL: ", nsec3param_answers[0].ttl
                print "----------------------------"
    if len(nsec3param_answers) >= 2:
        response['RRSIG'] = []
        for rdata in nsec3param_answers[1]:
            response['RRSIG'].append({
                "algorithm" : rdata.algorithm,
                "inception" : rdata.inception,
                "key_tag" : rdata.key_tag,
                "expiration" : rdata.expiration,
                "ttl" : nsec3param_answers[1].ttl
            })
            if output:
                print "  Algorithm: ", rdata.algorithm
                print "  Inception: ", rdata.inception
                print "  Key tag: ", rdata.key_tag
                print "  Expiration: ", rdata.expiration
                print "  TTL: ", nsec3param_answers[1].ttl
                print "----------------------------"

    return response



def nsec3_shiet(domain, dns_server = "8.8.8.8", output = False):
    nsec3_request = dns.message.make_query("nsec3testnoexist"+domain, dns.rdatatype.NSEC3)
    nsec3_request.want_dnssec()
    nsec3_answers = dns.query.udp(nsec3_request, dns_server, timeout=TIMEOUT)
    if nsec3_answers.flags & dns.flags.TC:
        nsec3_answers = dns.query.tcp(nsec3_request, dns_server, timeout=TIMEOUT)
    nsec3param_answers = nsec3_answers.authority

    if output:
        print "NSEC3" #hash alg, num of iter, salt, ttl
        print "============================"
    response = dict()

    for authority in nsec3param_answers:
        for rrset in authority:
            if rrset.__class__ == dns.rdtypes.ANY.NSEC3.NSEC3:
                print "got one!"





def all_the_shiet(domain, dns_server = "8.8.8.8", output = False):
    domain = dns.name.from_text(domain)
    if not domain.is_absolute():
        domain = domain.concatenate(dns.name.root)

    pool = multiprocessing.pool.ThreadPool(processes=1)
    dnskey_result = pool.apply_async(dnskey_shiet, (domain, dns_server, output))
    soa_result = pool.apply_async(soa_shiet, (domain, dns_server, output))
    ds_result = pool.apply_async(ds_shiet, (domain, dns_server, output))
    nsec3param_result = pool.apply_async(nsec3param_shiet, (domain, dns_server, output))

    response = dict()
    response['DNSKEY'] = dnskey_result.get()
    response['SOA'] = soa_result.get()
    response['DS'] = ds_result.get()
    response['NSEC3PARAM'] = nsec3param_result.get()

    if output:
        pprint.pprint(response)

    return response


#from https://www.v13.gr/blog/?p=239
def calc_keyid(flags, protocol, algorithm, st):
    """
    @param owner        The corresponding domain
    @param flags        The flags of the entry (256 or 257)
    @param protocol     Should always be 3
    @param algorithm    Should always be 5
    @param st           The public key as listed in the DNSKEY record.
                        Spaces are removed.
    @return The key tag
    """
    # Remove spaces and create the wire format
    st0 = st.replace(' ', '')
    st2 = struct.pack('!HBB', int(flags), int(protocol), int(algorithm))
    st2 += base64.b64decode(st0)

    # Calculate the tag
    cnt = 0
    for idx in xrange(len(st2)):
        s = struct.unpack('B', st2[idx])[0]
        if (idx % 2) == 0:
            cnt += s << 8
        else:
            cnt += s

    ret = ((cnt & 0xFFFF) + (cnt >> 16)) & 0xFFFF

    return (ret)


if __name__=='__main__':
    nsec3_shiet('protonmail.ch',output=True)