#!/usr/bin/python
import dns.name
import dns.message
import dns.query
import dns.flags
import multiprocessing
import sys
import pprint
import base64
import struct


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


def hash_algo_to_text(algo):
    if algo==0:
        return 'Reserved'
    elif algo==1:
        return 'SHA-1'
    elif algo==2:
        return 'SHA-256'
    elif algo==3:
        return 'GOST R 34.11-94'
    elif algo==4:
        return 'SHA-384'
    else:
        return 'Unassigned'



def rrset_to_dict(rrset,dic,section):

    for rr in rrset:
        d=dict()
        rectype = dns.rdatatype.to_text(rr.rdtype)
        if rectype not in dic:
            dic[rectype]=list()
        d['i_text']=rr.to_text()
        d['i_typeno'] = rr.rdtype
        d['i_typestr'] = rectype
        d['i_section'] = section

        for key in rr.__slots__:
            val = getattr(rr, key)
            d[key] = val

        if rectype=='DNSKEY':
            binkey = d['key']
            keyalgo = d['algorithm']
            b64key = base64.b64encode(binkey)
            d['i_key_base64'] = b64key
            d['i_key_tag'] = calc_keyid(rr.flags, rr.protocol, rr.algorithm, b64key)
            d['i_key_bits'] = len(binkey)*8 #TODO: this seems to be wrong
            d['i_key_algostr'] = dns.dnssec.algorithm_to_text(keyalgo)

        if rectype=='RRSIG':
            binsig=d['signature']
            b64sig = base64.b64encode(binsig)
            d['i_signature_base64'] = b64sig

        if rectype=='DS':
            digest_type=d['digest_type']
            d['i_digest_typestr'] = hash_algo_to_text(digest_type)

        dic[rectype].append(d)
    return dic


def query_to_dict(qname, qtype, nameserver='8.8.8.8', timeout=3, request_dnssec_records=True, check_disabled=True):
    request = dns.message.make_query(qname, qtype)
    if request_dnssec_records:
        request.want_dnssec()
    if check_disabled:
        request.flags |= dns.flags.CD

    reply = dns.query.udp(request, nameserver, timeout=timeout, one_rr_per_rrset=False)
    if reply.flags & dns.flags.TC:
        reply = dns.query.tcp(request, nameserver, timeout=timeout, one_rr_per_rrset=False)

    retval = dict()
    for section in ['answer', 'authority', 'additional']:
        for answer in getattr(reply,section):
            rrset_to_dict(answer, retval, section)


    rcode = reply.rcode()
    retval['_META']={
      #  'i_request_size' : request.request_payload,
      'i_rcode': rcode,
    'i_rcode_text': dns.rcode.to_text(rcode),
    } # question size, reply size, amplification factor, ... transport
    return retval



def dnsdict(domain,qtypes=None):
    if qtypes is None:
        qtypes = ['SOA', 'A', 'MX', 'DNSKEY', 'DS', 'NS']
    root = dict()
    local_dnssec = dict()
    remote_dnssec = dict()

    for t in qtypes:
        local_dnssec[t] = query_to_dict(domain, dns.rdatatype.from_text(t))
        remote_dnssec[t] = query_to_dict(domain, dns.rdatatype.from_text(t), check_disabled=False)

    local_dnssec['NSEC'] = query_to_dict('hzwhidntx.' + domain, dns.rdatatype.NSEC)
    local_dnssec['NSEC3'] = query_to_dict('hzwhidnty.' + domain, dns.rdatatype.NSEC3)

    root['LOCAL_DNSSEC'] = local_dnssec
    root['REMOTE_DNSSEC'] = remote_dnssec
    return root



if __name__=='__main__':
    if len(sys.argv)<2:
        print "arguments: <domain> [<qtype> ...]"
        sys.exit(1)
    domain = sys.argv[1]
    qtypes=None
    defargs=True
    if len(sys.argv)>2:
        defargs=False
        qtypes=[x.upper() for x in sys.argv[2:]]

    dndic=dnsdict(domain,qtypes)
    print pprint.pformat(dndic, width=1)
