package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class HeadScanTE extends SmuggleScanBox implements IScannerCheck {

        HeadScanTE(String name) {
            super(name);
        }

        private static Pattern H1_RESPONSE_LINE = Pattern.compile("HTTP/1[.][01] [0-9]");

        public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
            original = setupRequest(original);
            original = Utilities.addOrReplaceHeader(original, "Accept-Encoding", "identity");
            original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
            original = Utilities.addCacheBuster(original, Utilities.generateCanary());
            original = Utilities.replaceFirst(original, "HTTP/2", "HTTP/1.1");
            original = Utilities.addOrReplaceHeader(original, "X-Come-Out-And-Play", "1");
            byte[] base = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "chunked");
            base = Utilities.addOrReplaceHeader(base, "Connection", "keep-alive");
            //base = Utilities.setMethod(base, "HEAD"); // use 'force method name' instead
            //base = Utilities.setPath(base, "*");

            ArrayList<String> methods = new ArrayList<>();
            methods.add("HEAD");
            //methods.add("OPTIONS");
            //methods.add("GET");
            methods.add("POST");

            for (String method: methods) {
                base = Utilities.setMethod(base, method);
                ArrayList<String> attacks = new ArrayList<>();
                attacks.add("FOO BAR AAH\r\n\r\n");
//            attacks.put("invalid2", "GET / HTTP/1.2\r\nFoo: bar\r\n\r\n");
//            attacks.put("unfinished", "GET / HTTP/1.1\r\nFoo: bar");

                attacks.add(Utilities.helpers.bytesToString(Utilities.setMethod(Utilities.setPath(original, "/"), "GET")));
                // todo try collab-host here somewhere
                // todo try subdomain too
                // or should be just be a followup test? argh.

                //attacks.add(Utilities.helpers.bytesToString(Utilities.setPath(original, "/")));
                //attacks.add(Utilities.helpers.bytesToString(Utilities.setPath(original, "/")));
                //attacks.add(Utilities.helpers.bytesToString(original));
               // attacks.add(Utilities.helpers.bytesToString(original));

                String attackCode = String.join("|", config.keySet());
                for (String entry : attacks) {
                    byte[] attack = buildTEAttack(base, config, entry);
                    Resp resp = HTTP2Scan.h2request(service, attack);

                    if (mixedResponse(resp)) {
                        Resp baseResp = HTTP2Scan.h2request(service, Utilities.setMethod(original, method));
                        if (mixedResponse(baseResp)) {
                            continue;
                        }

                        report("Tunnel desync v9-6: TE-H2: " + attackCode, "", resp);
                        return true;
                    } else if (false && mixedResponse(resp, false)) { // disabled as it's too sketchy
                        recordCandidateFound();
                        SmuggleHelper helper = new SmuggleHelper(service);
                        helper.queue(Utilities.helpers.bytesToString(attack));
                        List<Resp> results = helper.waitFor();
                        if (mixedResponse(results.get(0), false)) {
                            report("Tunnel desync v9 TE-H1: " + attackCode, "", resp, results.get(0));
                        } else {
                            report("Tunnel desync v9 TE-H1 maybe: " + attackCode, "", resp);
                        }
//                    recordCandidateFound();
//                    Resp followup1 = request(service, Utilities.setMethod(attack, "GET"));
//                    if (!mixedResponse(followup1, false)) {
//
//                        Resp followup2 = request(service, Utilities.setMethod(attack, "FOO"));
//                        if (!mixedResponse(followup2, false)) {
//                            report("Head desync TE-H1v2: " + entry.getKey(), "", resp, followup1, followup2);
//                        }
//                    }
                    } else if (resp.failed()) {
                        return false;
                    }
                }
            }

            return false;
        }

        private byte[] buildTEAttack(byte[] base, HashMap<String, Boolean> config, String attack) {
            try {

                //new ChunkContentScan("xyz").DualChunkTE().

                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(makeChunked(base, attack.length(), 0, config, false));
                outputStream.write(attack.getBytes());
                return outputStream.toByteArray();
//                outputStream.write(base);
//                outputStream.write(attack.getBytes());
//                return makeChunked(outputStream.toByteArray(), 0, 0, config, false);

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        static boolean mixedResponse(Resp resp) {
            return mixedResponse(resp, true);
        }

        static boolean mixedResponse(Resp resp, boolean requireHTTP2) {
            if (!Utilities.containsBytes(Utilities.getBody(resp.getReq().getResponse()).getBytes(), "HTTP/1".getBytes())) {
                return false;
            }

            if (!H1_RESPONSE_LINE.matcher(Utilities.getBody(resp.getReq().getResponse())).find()) {
                return false;
            }

            if (requireHTTP2) {
                if (!Utilities.containsBytes(resp.getReq().getResponse(), "HTTP/2 ".getBytes())) {
                    return false;
                }
            } else {

                // todo could use connection: close in first request?

                // if the response is chunked, burp will rewrite using content-length
                // if there's no content-length then burp will truncate randomly based on packet size
                // no longer required thanks to turbo
//                if ("".equals(Utilities.getHeader(resp.getReq().getResponse(), "Content-Length"))) {
//                    return false;
//                }

                byte[] nestedResp = Utilities.getBodyBytes(resp.getReq().getResponse());
                if (Utilities.containsBytes(nestedResp, ": chunked\r\n".getBytes())) {
                    if (Utilities.containsBytes(nestedResp, "\r\n0\r\n".getBytes())) {
                        return false;
                    }
                } else {
                    // todo misses if the second response has no length
                    try {
                        int nestedCL = Integer.parseInt(Utilities.getHeader(nestedResp, "Content-Length"));
                        int realLength = nestedResp.length - Utilities.getBodyStart(nestedResp);
                        if (realLength+10 >= nestedCL) { // fixme +10 is workaround for 'real' not counting trailing whitespace
                            return false;
                        }
                    } catch (Exception e) {
                        return false;
                    }

                }

            }


            return true;
        }
}

