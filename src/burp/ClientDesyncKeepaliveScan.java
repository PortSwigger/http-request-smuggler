package burp;

import java.util.Arrays;
import java.util.List;

public class ClientDesyncKeepaliveScan extends Scan {

    ClientDesyncKeepaliveScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        String TRIGGER = "x=y\r\nZ";
        byte[] base = Utilities.setMethod(baseReq, "POST");
        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(TRIGGER.length()));
        List<String> contentTypes = Arrays.asList("application/x-www-form-urlencoded"); // , "multipart/form-data", "text/plain"

        for (String contentType: contentTypes) {
            base = Utilities.addOrReplaceHeader(base, "Content-Type", contentType);

            byte[] attack = Utilities.setBody(base, TRIGGER);
            SmuggleHelper helper = new SmuggleHelper(service, true);

            helper.queue(new String(attack));
            helper.queue(new String(attack));
            List<Resp> results = helper.waitFor();
            if (results.size() < 1) {
                return null;
            }

            if (results.size() < 2) {
                continue;
            }

            Resp first = results.get(0);
            Resp second = results.get(1);

            if (first.failed() || second.failed()) {
                continue;
            }

            if (helper.getConnectionCount() > 1) {
                continue;
            }

            if (first.getStatus() == second.getStatus()) {
                continue;
            }

            String prefix = "h1-confirmed";
            Utilities.supportsHTTP2 = true;

            //byte[] responseBytes = Utilities.callbacks.makeHttpRequest(service, attack, false).getResponse();
            Resp h2test = HTTP2Scan.h2request(service, attack, false);

            if (!h2test.failed() && Utilities.contains(h2test, "HTTP/2")) {
                prefix = "h2-blocked";
                Resp h2test2 = HTTP2Scan.h2request(service, attack, false);
                if (h2test.getStatus() != h2test2.getStatus()) {
                    report("Client-side h2 desnyc? ", "", first, second, h2test, h2test2);
                    return null;
                }
            }

            report("Browser desync (line2): "+ contentType.substring(0, 4) +"/"+prefix+ " |" + first.getStatus() + "|" + second.getStatus(), "", baseReq, first, second);
            return null;
        }
        return null;
    }
}