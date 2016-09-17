from flask import Flask, jsonify
app = Flask(__name__)
from dnssecchecks import all_tests, DNSInfoBroker, TESTRESULTTYPE_ERROR, TESTRESULTTYPE_SECURE, RESULTTYPE_BAD
import time

@app.route("/testdomain")
def testdomain():
    return "Hello World!"


@app.route('/d/<domainname>')
def checkdomain(domainname):
    testrun = DNSSECTest(domainname)
    testrun.run_tests()

    return jsonify(testrun.result_as_dict())



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
                continue

            self.testresults.append(testinstance)
            testinstance.run_test()

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
            if result.result_type == RESULTTYPE_BAD:
                score -= (score_subtract_per_test * result.result_weight )
            resultinfo = {
                "name": result.name,
                "description": result.description,
                "messages": result.result_messages
            }
            resultdict["tests"].append(resultinfo)

        if self.result_type == None:
            self.result_type = TESTRESULTTYPE_SECURE


        resultdict["result"] = self.result_type
        resultdict["score"] = int(score)
        
        return resultdict





if __name__ == "__main__":
    app.debug = True
    app.run()