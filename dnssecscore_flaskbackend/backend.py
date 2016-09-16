from flask import Flask
app = Flask(__name__)

@app.route("/testdomain")
def testdomain():
    return "Hello World!"

def checkdomain(domainname):
    testresult=dict()

    return flask.jsonify(testresult)


if __name__ == "__main__":
    app.run()