package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class H2TunnelScan extends SmuggleScanBox implements IScannerCheck {

    H2TunnelScan(String name) {
        super(name);
    } // todo don't show any permutations


    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
        if (!config.containsKey("vanilla")/* && !config.containsKey("space1") && !config.containsKey("connection")*/) {
            return false;
        }

        original = setupRequest(original);
        if (!Utilities.isHTTP2(original)) {
            original = Utilities.replaceFirst(original, " HTTP/1.1\r\n", " HTTP/2\r\n");
        }
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        //original = Utilities.setHeader(original, "Connection", "keep-alive");
        //original = Utilities.setMethod(original, "HEAD");
        //original = Utilities.addOrReplaceHeader(original, "null\u0000", "13");
        //original = Utilities.addOrReplaceHeader(original, ":connection", "Content-Length");
        original = Utilities.addOrReplaceHeader(original, "Via", "x (comment\u0000hmmm)");


        HashSet<String> methods = new HashSet<>();
        methods.add("GET");
        methods.add("POST");
        methods.add("HEAD");
        methods.add("OPTIONS");
        //original = Utilities.addOrReplaceHeader(original, ":method", "HEAD");
        original = Utilities.addCacheBuster(original, Utilities.generateCanary());

        for (String method: methods) {
            HashMap<String, String> attacks = new HashMap<>();
            attacks.put("invalid1", "FOO BAR AAH\r\n\r\n");
            //attacks.put("invalid2", "GET / HTTP/1.2\r\nFoo: bar\r\n\r\n");
            //attacks.put("unfinished", "GET / HTTP/1.1\r\nFoo: bar");
//            attacks.put("basic1", Utilities.helpers.bytesToString(original));
//            attacks.put("basic2", Utilities.helpers.bytesToString(original));
//            attacks.put("basic3", Utilities.helpers.bytesToString(original));
            //attacks.put("invalid1", "FOO BAR AAH\r\n\r\n");
            //attacks.put("invalid2", "GET / HTTP/1.2\r\nFoo: bar\r\n\r\n");
            //attacks.put("basic", "GET / HTTP/1.1\r\nHost: "+service.getHost()+"\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nConnection: close\r\n\r\n"); // Utilities.globalSettings.getString("collab domain")

            for (Map.Entry<String, String> entry : attacks.entrySet()) {
                byte[] attack = Utilities.setBody(original, entry.getValue());
                attack = Utilities.setMethod(attack, method);
                if (Utilities.globalSettings.getBoolean("strip CL")) {
                    attack = Utilities.replace(attack, "Content-Length", "fakecontentlength");
                } else {
                    attack = Utilities.setHeader(attack, "Content-Length", "0");
                }
                Resp resp = HTTP2Scan.h2request(service, attack);
                if (HeadScanTE.mixedResponse(resp)) {
                    report("Tunnel desync CLv2-1: " + method, "", resp);
                    break;
                }
            }
        }

//        for (Map.Entry<String, String> entry: attacks.entrySet()) {
//            byte[] attack = Utilities.addOrReplaceHeader(Utilities.setBody(original, "X=Y"+entry.getValue()), "Content-Length", "3");
//            Resp resp = request(service, attack);
//            if (HeadScanTE.mixedResponse(resp)) {
//                report("Head desync CLv1-3: "+entry.getKey(), "", resp);
//            } else if (HeadScanTE.mixedResponse(resp, false)) {
//                Resp followup = request(service, Utilities.setMethod(attack, "GET"));
//                if (!HeadScanTE.mixedResponse(followup, false)) {
//                    report("Head desync CLv3-0: "+entry.getKey(), "", resp);
//                }
//            }
//        }
        return false;
    }
}

