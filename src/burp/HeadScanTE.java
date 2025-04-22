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
            scanSettings.importSettings(DesyncBox.h2Settings);
            scanSettings.importSettings(DesyncBox.h2Permutations);
        }

        private static Pattern H1_RESPONSE_LINE = Pattern.compile("HTTP/1[.][01] [0-9]");

        public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
            original = setupRequest(original);
            if (!Utilities.isHTTP2(original)) {
                original = Utilities.replaceFirst(original, " HTTP/1.1\r\n", " HTTP/2\r\n");
            }
            original = Utilities.addOrReplaceHeader(original, "Accept-Encoding", "identity");
            original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
            original = Utilities.addCacheBuster(original, Utilities.generateCanary());
            original = Utilities.replaceFirst(original, "HTTP/2", "HTTP/1.1");
            //original = Utilities.addOrReplaceHeader(original, "X-Come-Out-And-Play", "1");
            byte[] base = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "chunked");
            //base = Utilities.addOrReplaceHeader(base, "Connection", "keep-alive");
            //base = Utilities.setMethod(base, "HEAD"); // use 'force method name' instead
            //base = Utilities.setPath(base, "*");

            ArrayList<String> methods = new ArrayList<>();

            for (int i=0; i<1; i+=1) {
                //methods.add("HEAD");
                //methods.add("OPTIONS");
                methods.add("GET");
                methods.add("POST");
            }

            //base = Utilities.addOrReplaceHeader(base, ":method", "HEAD ");

            //String foobar = "X\r\n\r\n";
            String foobar = "FOO BAR AAH\r\n\r\n";
            String foo = "FOO\r\n\r\n";
//            String foobar = "TRACE * HTTP/1.0\r\n\r\n";
//            String originalReq = Utilities.helpers.bytesToString(Utilities.setMethod(Utilities.setPath(original, "/"), "GET"));

//            padding makes this attack worse... unsure why
//            String padChunk = "F\r\nAAAAAAAAAAAAAAA\r\n";
//            StringBuilder fullPad = new StringBuilder();
//            for (int i=0; i<3000; i++) {
//                fullPad.append(padChunk);
//            }
//            foobar = foobar + fullPad.toString();
//            originalReq = originalReq + fullPad.toString();

            for (String method: methods) {
                base = Utilities.setMethod(base, method);

                if (!"HEAD".equals(method)) {
                    base = Utilities.addOrReplaceHeader(base, "x-http-method-override", "HEAD");
                    base = Utilities.addOrReplaceHeader(base, "x-http-method", "HEAD");
                    base = Utilities.addOrReplaceHeader(base, "x-method-override", "HEAD");
                    base = Utilities.addOrReplaceHeader(base, "real-method", "HEAD");
                    base = Utilities.addOrReplaceHeader(base, "request-method", "HEAD");
                    base = Utilities.addOrReplaceHeader(base, "method", "HEAD");
                }

                ArrayList<String> attacks = new ArrayList<>();
                attacks.add(foobar);
                attacks.add(foo);
//            attacks.put("invalid2", "GET / HTTP/1.2\r\nFoo: bar\r\n\r\n");
//            attacks.put("unfinished", "GET / HTTP/1.1\r\nFoo: bar");

               // attacks.add(originalReq);
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
                    } else if (resp.failed()) {
                        return false;
                    }
                }
            }

            return false;
        }

        static byte[] buildTEAttack(byte[] base, HashMap<String, Boolean> config, String attack) {
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
            if (!Utilities.containsBytes(Utilities.getBody(resp.getReq().getResponse()).getBytes(), "HTTP/1".getBytes())) {
                return false;
            }

            if (!H1_RESPONSE_LINE.matcher(Utilities.getBody(resp.getReq().getResponse())).find()) {
                return false;
            }


            if (!Utilities.containsBytes(resp.getReq().getResponse(), "HTTP/2 ".getBytes())) {
                return false;
            }

            return true;
        }
}

