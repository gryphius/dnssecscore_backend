# DNSSECSCORE

This is the backend code for the dnssec implementation tests currently hosted at dnssecscore.com

The idea of this project is to provide a service which will asses the DNSSEC implementation of a domain and give it a score
similar to the qualys SSL test for webservers.

## The tests can also be executed from the command line without flask

```
pip install dnsseccheck
dnssec_check dnssecscore.com
```

[![Travis build status](https://travis-ci.org/gryphius/dnssecscore_backend.svg?branch=master)](https://travis-ci.org/gryphius/dnssecscore_backend)

## Tests
| Test                                | Description           | Remarks | Implementation status  | Unit Test Coverage |
| ----------------------------------- | --------------------- | ------- | ---------------------- | ------------------ |
| check if zone is signed             | check if DNSKEY RR present| if not signed, abort and return I(nsecure) status | implemented | YES |
| dnssec validation check             | if validating resolver returns SRVFAIL but local check succeeds, assume validation error   | link to dnsviz/verisign for debugging validation erros | dns backend ready, test missing| NO |
| DS in parent                        | Test if the parent has DS for this zone      | if not, island of security and therefore T(rust) issue   | implemented |
| DS digest-type                      | Test if every keytag in the DS set provides SHA2    | SHA-1 vs. SHA-256 Considerations for DS Records https://tools.ietf.org/html/rfc4509#section-6.2, http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml    | implemented | NO |
| RRSIG for each DNSKEY algo          | 2.2 of RFC 4035 (narrow rollover)     |     | implemented | NO |
| RRSIG inception time          | RRSIG inception must be at least one hour earlier   | newer than 1h risks validation failure on resolver with clock skew issues    |implemented  | NO |
| RRSIG expiration time         | check max. expiration time of found RRSIGs   | risk of replay attacks     | implemented | NO |
| SOA expire vs. max. expiration time |    | risk of SERVFAIL responses from "stale" secondary    | | NO |
| DNSKEY RRSIG for each DS algo       | 2.2 of RFC 4035   (narrow rollover)    |     | implemented | NO |
| DNSKEY key size                     | e.g. RSA: lt 1024 bit is bad. gt 4096 is not supported by RFC   |     | backend info available, no test | NO |
| DNSKEY algorithm usage              | favor ECDSA keys  | see also https://tools.ietf.org/html/draft-wouters-sury-dnsop-algorithm-update-01  | implemented | NO |
| SEP Flag tests(ZSK vs KSK)          | check if DS point to KSKs only, check if the DNSKEY RRSET is only signed by KSK  |   | implemented | NO |
| dangling DS                         | check if there are DS without matching DNSKEY    | warning only, this could be valid (stand by key)| implemented | NO |
| number of DS                        | check number of DS RR in parent zone   | more than one spare DS is pointless | implemented | NO |
| nsec3 opt-out usage                 | check if zone is not using opt-out | see RFC5155, Security Considerations 12.2 | implemented | NO |
| nsec3 iterations                    | check max. number of iterations     | min. must not be checked | | NO |
| nsec3 salt                          | check max. length of salt     | min. must not be checked | | NO |
| nsec3 hash algorithm                | must be SHA1 (1)     |  | implemented | NO |
| negative answer                     | check negative answer size | the smaler the response size the better. NSEC vs NSEC3, nsec typically 2 (1x denial, 1x wildcard), nsec3 typically 3) | | NO |
| response size test                  | checks amplification factor of request/response ratio (e.g. test ANY, DNSKEY)   | favors ECC keys, non-NSEC3 usage, non-wildcard usage | | NO |
| number of DNSKEY                    | check number of DNSKEY RR in zone   | the fewer the better. CSK setup is favored because of smaller response size. Split key (KSK, ZSK) is ok. Temp. 3 keys during rollover acceptable. KSK and ZSK should not be rolled together to minimize DNSKEY RR Set size. | implemented | NO |


## Tests of additional records

| Test                                | Description           | Remarks | Implementation status  | Unit Test Coverage |
| ----------------------------------- | --------------------- | ------- | ---------------------- | ------------------ |
| tlsa mismatch                       | check if mx, www TLSA fingerprint matches TLS certificate hash      | | | NO |
| tlsa digest-type                    | check if mx, www TLSA digest type is not 1, at least 2 and optionally 3 or 4       | | | NO |
| sshfp digest-type                   | check if found SSHFP digest type is not 1, at least 2 and optionally 3 or 4     | | | NO |


## The test backend

 * to run the backend locally, you need python flask and dnspython ( ```pip install dnspython flask``` )
 * to start it locally, call python backend.py - this will start a webserver on port 5000 . 
  * To get the testresult as json, open http://127.0.0.1:5000/d/example.org (replace example.org with the domain you want to test)
  * To see all available DNS information, open http://127.0.0.1:5000/dnsdict/example.org Note that this is *not* valid json, it just prints out the dict as returned by the DNS backend
 
 
## The DNS dictionary

before test are run, all necessary DNS lookups are done using the dnspython library.  The lookups are peformed twice, with/without DO bit set.
The backend puts all result in a nested dictionary and enriches them with additional information (all fields below starting with i_ )

Example dict: (test locally with http://127.0.0.1:5000/dnsdict/example.org to get the most current version)
 
```
{'LOCAL_DNSSEC': {'A': {'A': [{'address': '50.19.109.98',
                               'i_section': 'answer',
                               'i_text': '50.19.109.98',
                               'i_typeno': 1,
                               'i_typestr': 'A'}],
                        'RRSIG': [{'algorithm': 13,
                                   'expiration': 1475775837,
                                   'i_section': 'answer',
                                   'i_signature_base64': 'sXuZTdsyF5SG02QmsrVQ7phvMHA17xkRGK15Eg1XRh5DkvUIS6+za7pzmO5KO6E4Vbpn6jGrJrMb1j/A88Hoxw==',
                                   'i_text': 'A 13 2 300 20161006174357 20160922174357 52605 example.org. sXuZTdsyF5SG02QmsrVQ7phvMHA17xkR GK15Eg1XRh5DkvUIS6+za7pzmO5KO6E4 Vbpn6jGrJrMb1j/A88Hoxw==',
                                   'i_typeno': 46,
                                   'i_typestr': 'RRSIG',
                                   'inception': 1474566237,
                                   'key_tag': 52605,
                                   'labels': 2,
                                   'original_ttl': 300,
                                   'signature': '\xb1{\x99M\xdb2\x17\x94\x86\xd3d&\xb2\xb5P\xee\x98o0p5\xef\x19\x11\x18\xady\x12\rWF\x1eC\x92\xf5\x08K\xaf\xb3k\xbas\x98\xeeJ;\xa18U\xbag\xea1\xab&\xb3\x1b\xd6?\xc0\xf3\xc1\xe8\xc7',
                                   'signer': ,
                                   'type_covered': 1}],
                        '_META': {'i_rcode': 0, 'i_rcode_text': 'NOERROR'}},
                  'DNSKEY': {'DNSKEY': [{'algorithm': 13,
                                         'flags': 256,
                                         'i_calculated_ds': {1: '24227998A007DC6F6ABBA06D21F3F9DEFE5B7F51',
                                                             2: 'BECFF2B002FB736F9916489F21E00A8E43597289575294C5CFD068EDB2FA95EA',
                                                             4: 'DE5086AD5EF5D7C1F27A563EAD4AFAC2DF29D0E87E852AF35FC15C2D0ACC5F5E43C3F07B5F0D21BBEA3FC588C9FE790E'},
                                         'i_key_algostr': 'ECDSAP256SHA256',
                                         'i_key_base64': 'kS97hC6is6jqBtK5/QNI5PTVi6zrD9/3jAV0MU2Bexhuk+1oWXF/7mgZCurKG9fregV0Gc0d4zAkR7j3H9Pdhg==',
                                         'i_key_tag': 52605,
                                         'i_section': 'answer',
                                         'i_text': '256 3 13 kS97hC6is6jqBtK5/QNI5PTVi6zrD9/3 jAV0MU2Bexhuk+1oWXF/7mgZCurKG9fr egV0Gc0d4zAkR7j3H9Pdhg==',
                                         'i_typeno': 48,
                                         'i_typestr': 'DNSKEY',
                                         'key': '\x91/{\x84.\xa2\xb3\xa8\xea\x06\xd2\xb9\xfd\x03H\xe4\xf4\xd5\x8b\xac\xeb\x0f\xdf\xf7\x8c\x05t1M\x81{\x18n\x93\xedhYq\x7f\xeeh\x19\n\xea\xca\x1b\xd7\xebz\x05t\x19\xcd\x1d\xe30$G\xb8\xf7\x1f\xd3\xdd\x86',
                                         'protocol': 3},
                                        {'algorithm': 13,
                                         'flags': 257,
                                         'i_calculated_ds': {1: 'ED25C043A242D798D58A0682AADF569D8DBF42A5',
                                                             2: 'B174B0FD099BC3AA49DDCBECCBC00B988AD4DCAF24222110238FB1A2ABB7DB0F',
                                                             4: '0A946D2DDE61765C63BC050771183A3BA6F87C7F92DC6A1E77B7858A1E26134E2BD04AB0765BBFAA01EF992340CDCD67'},
                                         'i_key_algostr': 'ECDSAP256SHA256',
                                         'i_key_base64': 'jhtYS9l01pTtADKk43mMKUkHEYjvswQl0hATfez+cWm9r1NPttjsgKGAFBdp0q6fIkgepJl99ogAnBo+cq9jzQ==',
                                         'i_key_tag': 210,
                                         'i_section': 'answer',
                                         'i_text': '257 3 13 jhtYS9l01pTtADKk43mMKUkHEYjvswQl 0hATfez+cWm9r1NPttjsgKGAFBdp0q6f IkgepJl99ogAnBo+cq9jzQ==',
                                         'i_typeno': 48,
                                         'i_typestr': 'DNSKEY',
                                         'key': '\x8e\x1bXK\xd9t\xd6\x94\xed\x002\xa4\xe3y\x8c)I\x07\x11\x88\xef\xb3\x04%\xd2\x10\x13}\xec\xfeqi\xbd\xafSO\xb6\xd8\xec\x80\xa1\x80\x14\x17i\xd2\xae\x9f"H\x1e\xa4\x99}\xf6\x88\x00\x9c\x1a>r\xafc\xcd',
                                         'protocol': 3}],
                             'RRSIG': [{'algorithm': 13, # same RRSIG schema as in the example earlier
                             '_META': {'i_rcode': 0,
                                       'i_rcode_text': 'NOERROR'}},
                  'DS': {'DS': [{'algorithm': 13,
                                 'digest': '\xb1t\xb0\xfd\t\x9b\xc3\xaaI\xdd\xcb\xec\xcb\xc0\x0b\x98\x8a\xd4\xdc\xaf$"!\x10#\x8f\xb1\xa2\xab\xb7\xdb\x0f',
                                 'digest_type': 2,
                                 'i_digest_typestr': 'SHA-256',
                                 'i_digeststr': 'B174B0FD099BC3AA49DDCBECCBC00B988AD4DCAF24222110238FB1A2ABB7DB0F',
                                 'i_section': 'answer',
                                 'i_text': '210 13 2 b174b0fd099bc3aa49ddcbeccbc00b988ad4dcaf24222110238fb1a2abb7db0f',
                                 'i_typeno': 43,
                                 'i_typestr': 'DS',
                                 'key_tag': 210}],
                         'RRSIG': ...,
                         '_META': {'i_rcode': 0, 'i_rcode_text': 'NOERROR'}},
                  'MX':...
                  'NS':...
                  'NSEC': ...
                  'NSEC3': ...
 'REMOTE_DNSSEC': {'A': {'A': [{'address': '50.19.109.98', # ... query results without the DO bit set)
}
```