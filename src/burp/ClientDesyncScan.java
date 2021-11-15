package burp;

import java.util.Arrays;
import java.util.List;

public class ClientDesyncScan extends Scan {

    ClientDesyncScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        //redirScan(baseReq, service);
        waitScan(baseReq, service);
        return null;
    }

    void waitScan(byte[] baseReq, IHttpService service) {
        baseReq = Utilities.replaceFirst(baseReq, "Connection: close", "Connection: keep-alive");
        byte[] base = Utilities.setMethod(baseReq, "POST");
        //base = Utilities.setPath(base, "/%2f%3fx"); // robots.txt
        base = Utilities.addOrReplaceHeader(base, "Content-Type", "application/x-www-form-urlencoded");
        base = Utilities.addOrReplaceHeader(base, "Connection", "keep-alive");
        String followup = Utilities.helpers.bytesToString(baseReq);

        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(followup.length()));
        base = ChunkContentScan.bypassContentLengthFix(base);
        base = Utilities.setBody(base, "");

        List<String> contentTypes = Arrays.asList("application/x-www-form-urlencoded", "multipart/form-data", "text/plain");
        for (String contentType: contentTypes) {

            base = Utilities.setHeader(base, "Content-Type", contentType);
            TurboHelper helper = new TurboHelper(service, true);
            helper.setTimeout(2);
            helper.queue(new String(base));
            helper.queue(followup);
            List<Resp> results = helper.waitFor();
            if (results.size() < 2) {
                continue;
            }
            if (helper.getConnectionCount() > 1 || results.get(0).failed() || results.get(1).failed()) {
                continue;
            }

            if (BulkScan.domainAlreadyFlagged(service)) {
                continue;
            }

            Resp h2test = HTTP2Scan.h2request(service, base, false);
            String prefix = "h1";
            if (!h2test.failed() && Utilities.contains(h2test, "HTTP/2")) {
                prefix = "h2-blocked";
            }

            report("Client-side tunnel-desync v3 "+prefix, "", baseReq, results.get(0), results.get(1));
            return;
        }
    }

    // todo remove; made redundant by BrowserDesyncScan
    void reflectScan(byte[] baseReq, IHttpService service) {
        byte[] base = Utilities.setMethod(baseReq, "POST");
        base = Utilities.setPath(base, "/robots.txt");

        String POISON = "dlvywmzk";
        String HARMLESS = "boringzz";
        String TRIGGER = "GET /"+POISON+" HTTP/1.1\r\nX: Y";
        String VICTIM = "GET /"+HARMLESS+" HTTP/1.1\r\nX: Y";
        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(TRIGGER.length()));

        List<String> contentTypes = Arrays.asList("application/x-www-form-urlencoded", "multipart/form-data", "text/plain");
        trytechnique:
        for (String contentType: contentTypes) {
            base = Utilities.addOrReplaceHeader(base, "Content-Type", contentType);

            byte[] attack = Utilities.setBody(base, TRIGGER);
            byte[] followup = Utilities.setBody(base, VICTIM);
            Resp h2attack = HTTP2Scan.h2request(service, attack, false);
            if (h2attack.failed()) {
                return;
            }
            Resp victim = HTTP2Scan.h2request(service, followup, false);
            if (Utilities.contains(victim, POISON)) {
                report ("Client-side h2 reflection-desync", "", baseReq, h2attack, victim);
            }

        }
    }

    // todo remove; made redundant by BrowserDesyncScan
    void redirScan(byte[] baseReq, IHttpService service) {
        byte[] base = Utilities.setMethod(baseReq, "POST");
        base = Utilities.setPath(base, "/robots.txt");
        base = Utilities.addOrReplaceHeader(base, "Content-Type", "application/x-www-form-urlencoded");
        String target = service.getHost().replaceAll("[.]", "-") + ".7t1t0sod4lwcw9d4yh3dsrflzc56tv.psres.net";

        if (service.getHost().contains(".nab")) {
            return;
        }

        String TRIGGER = String.format(
                "GET / HTTP/1.1\r\n" +
                        "Host: %s\r\n"+
                        "Referer: http://ref.%s/\r\n" +
                        "X-Forwarded-For: xff.%s\r\n" +
                        "Dud: dud.%s\r\n" +
                        "True-Client-IP: tci.%s\r\n" +
                        "\r\n", service.getHost(), target, target, target, target);
        //String TRIGGER = "GET /assets HTTP/1.1\r\nHost: "+target+"\r\nX-Forwarded-For: "+target+"\r\nFoo: ";
        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(TRIGGER.length()));
        base = Utilities.setBody(base, TRIGGER);
        request(service, base);
        //HTTP2Scan.h2request(service, base, false);
    }


}
