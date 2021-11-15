package burp;

import java.util.Arrays;
import java.util.List;

public class OldClientDesyncScan extends Scan {

    OldClientDesyncScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {

        // won't work, breaks SSL
        String POISON = service.getHost()+".vkj193x6bpt14pbeyinhs9j50w6oud.psres.net";
        String HARMLESS = service.getHost()+".vkj193x6bpt15pbeyinhs9j50w6oud.psres.net";
        String TRIGGER = "GET /"+POISON+" HTTP/1.1\r\nX: Y";
        String VICTIM = "GET /"+HARMLESS+" HTTP/1.1\r\nX: Y";
        byte[] base = Utilities.setMethod(baseReq, "POST");
        base = Utilities.setPath(base, "/");
        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(TRIGGER.length()));
        List<String> paths = Arrays.asList("/robots.txt"); // "//", "/%", "/index.html" "/robots.txt"
        List<String> contentTypes = Arrays.asList("application/x-www-form-urlencoded"); // application/x-www-form-urlencoded, "multipart/form-data", "text/plain"
        String contentType = contentTypes.get(0);

        trytechnique:
        for (String path: paths) {
            base = Utilities.setPath(base, path);
            base = Utilities.addOrReplaceHeader(base, "Content-Type", contentType);

            byte[] attack = Utilities.setBody(base, TRIGGER);
            byte[] followup = Utilities.setBody(base, VICTIM);

            Resp first = null;
            Resp second = null;
            boolean reflectConfirmed = false;
            for (int i=0; i<4; i++) {
                TurboHelper helper = new TurboHelper(service, true);
                helper.queue(new String(attack));
                helper.queue(new String(followup));
                List<Resp> results = helper.waitFor();
                if (results.size() < 1) {
                    return null;
                }

                if (results.size() < 2) {
                    continue trytechnique;
                }

                first = results.get(0);
                second = results.get(1);

                if (first.failed() || second.failed()) {
                    continue trytechnique;
                }

                if (Utilities.contains(second, POISON)) {
                    reflectConfirmed = true;
                    break;
                }

                if (helper.getConnectionCount() > 1) {
                    continue trytechnique;
                }

                if (first.getStatus() == second.getStatus()) {
                    continue trytechnique;
                }
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

            String evidence = "";
            if (reflectConfirmed) {
                evidence = "reflected";
            } else {
                evidence =  first.getStatus() + "|" + second.getStatus();
            }

            String redirLocation = Utilities.getHeader(first.getReq().getResponse(), "Location");
            if (redirLocation.startsWith("https://www."+service.getHost()) || redirLocation.equals("") || redirLocation.startsWith("/") || redirLocation.startsWith("https://"+service.getHost())) {
                report("Browser desync (good target): "+ contentType.substring(0, 4) +"/"+prefix+ " |"+evidence, "", baseReq, first, second);
            }
            else {
                if (!BulkScan.domainAlreadyFlagged(service)) {
                    report("Browser desync (bad target): " + contentType.substring(0, 4) + "/" + prefix + " |" + evidence, "", baseReq, first, second);
                }
            }
            return null;
        }
        return null;
    }
}