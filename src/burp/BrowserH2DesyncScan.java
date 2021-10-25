package burp;

import java.util.Arrays;
import java.util.List;

public class BrowserH2DesyncScan extends Scan {

    BrowserH2DesyncScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        //redirScan(baseReq, service);
        waitScan(baseReq, service);
        return null;
    }

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

    void waitScan(byte[] baseReq, IHttpService service) {
        byte[] base = Utilities.setMethod(baseReq, "POST");
        //base = Utilities.setPath(base, "/robots.txt");
        base = Utilities.addOrReplaceHeader(base, "Content-Type", "application/x-www-form-urlencoded");
        String followup = "GET /robots.txt HTTP/1.1\r\nHost: "+service.getHost()+"\r\n\r\n";

        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(followup.length()));
        base = ChunkContentScan.bypassContentLengthFix(base);
        base = Utilities.setBody(base, "");

        // todo reduce timeout
        TurboHelper helper = new TurboHelper(service, true);
        helper.queue(new String(base));
        helper.queue(followup);
        List<Resp> results = helper.waitFor();
        if (results.size() < 2) {
            return;
        }
        if (helper.getConnectionCount() > 1 || results.get(0).failed() || results.get(1).failed()) {
            return;
        }

        if (BulkScan.domainAlreadyFlagged(service)) {
            return;
        }

        report ("Client-side tunnel-desync v2", "", baseReq, results.get(0), results.get(1));
    }
}
