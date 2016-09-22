# DNSSECSCORE

This is the backend code for the dnssec implementation tests currently hosted at dnssecscore.com

The idea of this project is to provide a service which will asses the DNSSEC implementation of a domain and give it a score
similar to the qualys SSL test for webservers.



## Tests


## Tests
| Test                                | Description           | Remarks | Implementation status  | Unit Test Coverage |
| ----------------------------------- | --------------------- | ------- | ---------------------- | ------------------ |
| check if zone is signed             | check if DNSKEY RR present| if not signed, abort and return I(nsecure) status | implemented | NO | 
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


## Backend

