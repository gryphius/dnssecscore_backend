from flask import Flask, jsonify
app = Flask(__name__)
from dnssecchecks import all_tests, DNSInfoBroker, TESTRESULTTYPE_ERROR, TESTRESULTTYPE_SECURE, RESULTTYPE_BAD, RESULTTYPE_WARNING
import time
import pprint
import traceback
from dnsdict import dnsdict

@app.route('/dnsdict/<domainname>')
def dndsict(domainname):
    dic = dnsdict(domainname, timeout=6)
    pretty=pprint.pformat(dic)
    tmpl="<PRE>%s</PRE>"%pretty
    return tmpl


@app.route('/d/<domainname>')
def checkdomain(domainname):
    try:
        testrun = DNSSECTest(domainname)
        testrun.run_tests()
        return jsonify(testrun.result_as_dict())
    except Exception:
        print traceback.format_exc()
        errdic= {
            "startdate": int(time.time()),
            "domain": domainname,
            "total_tests": len(all_tests),
            "tests":[],
            "result": TESTRESULTTYPE_ERROR,
            "score":0,
            "tests":[
                {
                    'name': "Oops",
                    'description': "something went wrong",
                    'messages': ['we are having trouble performing the tests. this is probably a bug on our side',],
                    'result_type': RESULTTYPE_BAD,
                }
            ],
        }

        return jsonify(errdic)




class DNSSECTest(object):
    def __init__(self, domain):
        self.testresults=[]
        self.domain = domain
        self.broker = DNSInfoBroker(domain)
        self.result_type = None
        self.startdate = int(time.time())

    def run_tests(self):
        for testclass in all_tests:
            testinstance = testclass(self.broker)
            if not testinstance.do_we_have_what_we_need():
                print "Test %s skipped - missing info"%testinstance.name
                continue

            self.testresults.append(testinstance)
            try:
                testinstance.run_test()
            except:
                print traceback.format_exc()
                testinstance.result_type = RESULTTYPE_BAD
                self.result_type = TESTRESULTTYPE_ERROR
                testinstance.result_messages= ['something went wrong while running this test and we had to abort... sorry!']
                break

            # abort tests
            if testinstance.shortcircuit!=None:
                self.result_type = testinstance.shortcircuit
                break


    def result_as_dict(self):
        resultdict = {
            "startdate": self.startdate,
            "domain": self.domain,
            "total_tests": len(all_tests),
            "tests":[],
        }

        score = 100
        score_subtract_per_test = 100.0/(len(all_tests))

        for result in self.testresults:
            if result.result_type in ( RESULTTYPE_BAD, RESULTTYPE_WARNING):
                score -= (score_subtract_per_test * result.result_weight )
            resultinfo = {
                "name": result.name,
                "description": result.description,
                "messages": result.result_messages,
                "result_type": result.result_type,
            }
            resultdict["tests"].append(resultinfo)

        if self.result_type == None:
            self.result_type = TESTRESULTTYPE_SECURE

        resultdict["result"] = self.result_type
        resultdict["score"] = int(score)

        return resultdict



if __name__ == "__main__":
    app.debug = True
    app.run(host= '0.0.0.0')