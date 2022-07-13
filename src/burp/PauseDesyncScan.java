package burp;

import java.util.Arrays;
import java.util.List;

public class PauseDesyncScan extends Scan {

    PauseDesyncScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        baseReq = Utilities.replaceFirst(baseReq, "Connection: close", "Connection: keep-alive");
        baseReq = Utilities.convertToHttp1(baseReq);

        // This is where we POST to
        String targetPath = Utilities.getPathFromRequest(baseReq); // +"?"+targetCanary;
        String targetCanary = "wrtz"+Utilities.generateCanary();
        byte[] targetExpect = targetCanary.getBytes();
        //String targetPath = "/favicon.ico?"+targetCanary+"=1";

        baseReq = Utilities.setPath(baseReq, targetPath);

        String poisonCanary = "wrtz"+Utilities.generateCanary();
        String poisonPath = "/favicon.ico?"+poisonCanary+"=1";
        byte[] poisonExpect = "ype: image/".getBytes();
        byte[] followUp = Utilities.setPath(baseReq, targetPath);

        Resp resp = request(service, followUp, 0, true);
        if (resp.failed() || Utilities.containsBytes(resp.getReq().getResponse(), poisonExpect)) {
            return null;
        }

        String payload = "GET "+poisonPath+" HTTP/1.1\r\nX: Y";
        //String victim = Utilities.helpers.bytesToString(Utilities.setPath(baseReq, poisonPath));
        byte[] base = Utilities.addOrReplaceHeader(baseReq, "Content-Type", "application/x-www-form-urlencoded");
        base = Utilities.addOrReplaceHeader(base, "Content-Length", "20");
        //base = Utilities.setMethod(base, "POST");
        base = Utilities.setBody(base, payload);
        //base = Utilities.fixContentLength(base);

        int burpTimeout = Integer.parseInt(Utilities.getSetting("project_options.connections.timeouts.normal_timeout"));
        TurboHelper helper = new TurboHelper(service, true, burpTimeout+1);
        int pauseBefore = payload.length() * -1;

        // TODO make this configurable
        Resp r1 = helper.blockingRequest(base, pauseBefore, 61000);
        //Resp r1 = helper.blockingRequest(base);
        if (r1.failed() || Utilities.contains(r1, "Connection: close")) {
            helper.waitFor(1);
            return null;
        }

        Resp r2 = helper.blockingRequest(followUp);
        helper.waitFor(1);
        if (r2.failed()) {
            return null;
        }

        // todo filter out regular CSD
        String title = null;
        if (Utilities.containsBytes(r2.getReq().getResponse(), poisonCanary.getBytes())) {
            title = "Pause-based desync - reflect";
        } else if (Utilities.containsBytes(r2.getReq().getResponse(), poisonExpect)) {
            title = "Pause-based desync - expected-response";
        } else if (!(resp.getStatus() == r2.getStatus()) && !Utilities.containsBytes(r2.getReq().getResponse(), targetExpect) && !Utilities.containsBytes(r2.getReq().getResponse(), targetCanary.getBytes())) {
            title = "Pause-based desync - status";
        }

        if (title == null) {
            return null;
        }

        byte[] timeoutplz = ChunkContentScan.bypassContentLengthFix(base);
        timeoutplz = Utilities.setBody(timeoutplz, "x");
        Resp hopefullyFail = request(service, timeoutplz, 0, true);
        if (!hopefullyFail.failed()) {
            // probably a client-side issue
            return null;
        }

        report(title, "", baseReq, r1, r2, resp);

        return null;
    }
}
