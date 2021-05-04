package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class HeadScanCL extends SmuggleScanBox implements IScannerCheck {

    HeadScanCL(String name) {
        super(name);
    }


    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
        if (!config.containsKey("vanilla")) {
            return false;
        }

        original = setupRequest(original);
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.setHeader(original, "Connection", "keep-alive");
        //original = Utilities.setMethod(original, "HEAD");

        HashSet<String> methods = new HashSet<>();
        methods.add("GET");
        methods.add("POST");
        methods.add("HEAD");
        methods.add("OPTIONS");

        for (String method: methods) {
            HashMap<String, String> attacks = new HashMap<>();
            attacks.put("invalid1", "FOO BAR AAH\r\n\r\n");
            attacks.put("invalid2", "GET / HTTP/1.2\r\nFoo: bar\r\n\r\n");
            attacks.put("unfinished", "GET / HTTP/1.1\r\nFoo: bar");
            attacks.put("basic1", Utilities.helpers.bytesToString(original));
            attacks.put("basic2", Utilities.helpers.bytesToString(original));
            attacks.put("basic3", Utilities.helpers.bytesToString(original));
            //attacks.put("invalid1", "FOO BAR AAH\r\n\r\n");
            //attacks.put("invalid2", "GET / HTTP/1.2\r\nFoo: bar\r\n\r\n");
            //attacks.put("basic", "GET / HTTP/1.1\r\nHost: "+service.getHost()+"\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nConnection: close\r\n\r\n"); // Utilities.globalSettings.getString("poc-collab domain")

            for (Map.Entry<String, String> entry : attacks.entrySet()) {
                byte[] attack = Utilities.setBody(original, entry.getValue());
                attack = Utilities.setMethod(attack, method);
                if (Utilities.globalSettings.getBoolean("strip CL")) {
                    attack = Utilities.replace(attack, "Content-Length", "fakecontentlength");
                } else {
                    attack = Utilities.setHeader(attack, "Content-Length", "0");
                }
                Resp resp = request(service, attack);
                if (HeadScanTE.mixedResponse(resp)) {
                    report("Tunnel desync CLv2-1: " + method, "", resp);
                    break;
                } else if (HeadScanTE.mixedResponse(resp, false)) {
                    Resp followup = request(service, Utilities.setMethod(attack, "GET"));
                    if (!HeadScanTE.mixedResponse(followup, false)) {
                        report("Tunnel desync CL-H1: " + method, "", resp, followup);
                        break;
                    }
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

