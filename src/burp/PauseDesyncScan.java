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


        byte[] targetExpect = "Content-Type: image/".getBytes();
        String targetCanary = "wrtz"+Utilities.generateCanary();
        String targetPath = "/favicon.ico?"+targetCanary+"=1";
        baseReq = Utilities.setPath(baseReq, targetPath);

        String canary = "wrtz"+Utilities.generateCanary();
        String poisonPath = "/robots.txt?"+canary+"=1";
        byte[] poisonExpect = "llow:".getBytes();
        byte[] followUp = Utilities.setPath(baseReq, targetPath);

        Resp resp = request(service, followUp, 0, true);
        if (resp.failed() || Utilities.containsBytes(resp.getReq().getResponse(), poisonExpect)) {
            return null;
        }

        String victim = Utilities.helpers.bytesToString(Utilities.setPath(baseReq, poisonPath));
        byte[] base = Utilities.addOrReplaceHeader(baseReq, "Content-Type", "application/x-www-form-urlencoded");
        base = Utilities.addOrReplaceHeader(base, "Content-Length", "20");
        //base = Utilities.setMethod(base, "POST");
        base = Utilities.setBody(base, victim);
        //base = Utilities.fixContentLength(base);

        int burpTimeout = Integer.parseInt(Utilities.getSetting("project_options.connections.timeouts.normal_timeout"));
        TurboHelper helper = new TurboHelper(service, true, burpTimeout+1);
        int pauseBefore = victim.length() * -1;
        Resp r1 = helper.blockingRequest(base, pauseBefore, burpTimeout*1000); // TODO make sure we delay body & explode on early response
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

        // if we get to here, either the server timeout is higher than ours or something is sketchy
        String title = null;
        if (Utilities.containsBytes(r2.getReq().getResponse(), canary.getBytes())) {
            title = "Unknown-side CL.0 desync reflect";
        } else if (Utilities.containsBytes(r2.getReq().getResponse(), poisonExpect)) {
            title = "Unknown-side CL.0 desync good";
        } else if (!(resp.getStatus() == r2.getStatus()) && !Utilities.containsBytes(r2.getReq().getResponse(), targetExpect) && !Utilities.containsBytes(r2.getReq().getResponse(), targetCanary.getBytes())) {
            title = "Unknown-side CL.0 desync status";
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
