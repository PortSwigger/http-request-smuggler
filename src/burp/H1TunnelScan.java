package burp;

import org.apache.commons.lang3.tuple.Pair;

import java.util.HashMap;
import java.util.List;

import static burp.ChunkContentScan.getCLTEAttack;
import static burp.ChunkContentScan.getTECLAttack;
import static burp.Utilities.getPathFromRequest;
import static burp.Utilities.helpers;

public class H1TunnelScan extends SmuggleScanBox implements IScannerCheck {

    H1TunnelScan(String name) {
        super(name);
        scanSettings.importSettings(DesyncBox.h1Permutations);
        scanSettings.importSettings(DesyncBox.h1Settings);
    }

    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {

        if(service.getHost().contains(".acss.att.com")) {
            return false;
        }

        original = setupRequest(original);
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.addOrReplaceHeader(original, "Connection", "keep-alive");

        byte[] base = Utilities.addOrReplaceHeader(original, "x-http-method-override", "HEAD");
        base = Utilities.setMethod(base, "HEAD");
        base = Utilities.addOrReplaceHeader(base, "x-http-method", "HEAD");
        base = Utilities.addOrReplaceHeader(base, "x-method-override", "HEAD");
        base = Utilities.addOrReplaceHeader(base, "real-method", "HEAD");
        base = Utilities.addOrReplaceHeader(base, "request-method", "HEAD");
        base = Utilities.addOrReplaceHeader(base, "method", "HEAD");
        base = Utilities.addOrReplaceHeader(base, "Transfer-Encoding", "chunked");

        final String TRIGGER = "FOO BAR AAH\r\n\r\n";

        timeTunnel(service, config, base, TRIGGER, true);
        timeTunnel(service, config, base, TRIGGER, false);

        return false;






//        boolean timeWorked = H1TimeTunnel(base, service, config);
//        if (!timeWorked) {
//            return false;
//        }
//
//        String nestedRespCode = getPathFromRequest(nestedRespBytes);
//        Resp bad = request(service, TRIGGER.getBytes(), 3, true);
//        String nonNestedCode = getPathFromRequest(bad.getReq().getResponse());
//
//        if (nestedRespCode.equals(nonNestedCode)) {
//            return false;
//        }
//
//        TurboHelper helper = new TurboHelper(service, true);
//        helper.queue(new String(original));
//        helper.queue(TRIGGER);
//        List<Resp> results = helper.waitFor();
//        if (results.size() < 2) {
//            return false;
//        }
//
//        if ("null".equals(new String(results.get(0).getReq().getResponse()))) {
//            return false;
//        }
//
//        // followup - send two requests non-smuggled, turbo-style. confirm second is different
//        // second is gonna be null unless I use turbo
//        String naturalNested = String.valueOf(results.get(1).getStatus());
//
//        if (naturalNested.equals(nestedRespCode)) {
//            // warning: this approach misses targets that don't support pipelining
//            // to detect those, use SecondRequestScan instead
//            report("Nested-diff plus pipelining: "+nonNestedCode+":"+nestedRespCode," ", resp, bad, results.get(0), results.get(1));
//            return false;
//        }
//
//        // bail if turbo had to reconnect for the second request
//        if (helper.getConnectionCount() > 1) {
//            report("Keepalive-fail: "+nonNestedCode+":"+nestedRespCode," ", resp, bad, results.get(0), results.get(1));
//            return false;
//        }
//
//        //if (Utilities.getHeader(results.get(0).getReq().getResponse()))
//
//        // byte[] brokenAttackReq = Utilities.replace(attackReq, "ransfer", "zansfer");
//        // byte[] brokenAttackReq = Utilities.replace(attackReq, "Content-Length", "Content-Cake");
//
//        String title = "H1-Tunnel "+nonNestedCode+":"+nestedRespCode;
//        if (!"".equals(nonNestedCode)) {
//            title += " good";
//        }
//        if (timeWorked) {
//            title += " [time-confirmed]";
//        }
//
//        report(title, "", resp, bad, results.get(0), results.get(1));
//        return true;
    }

    private boolean timeTunnel(IHttpService service, HashMap<String, Boolean> config, byte[] base, String TRIGGER, boolean CLTE) {
        // todo support CL.0
        Pair<String, Integer> attack;
        if (CLTE) {
            attack = getCLTEAttack(base, TRIGGER, config);
        } else {
            attack = getTECLAttack(base, TRIGGER, config);
        }

        Resp resp = request(service, helpers.stringToBytes(attack.getLeft()), 0, true);
        byte[] nestedRespBytes = Utilities.getNestedResponse(resp.getReq().getResponse());
        if (nestedRespBytes == null) {
            return true;
        }


        TurboHelper helper = new TurboHelper(service, true);
        helper.queue(attack.getLeft(), attack.getRight(), 4000);
        List<Resp> results = helper.waitFor();
        Resp pauseReq = results.get(0);
        if (pauseReq.failed()) {
            return true;
        }

        nestedRespBytes = Utilities.getNestedResponse(pauseReq.getReq().getResponse());
        if (nestedRespBytes == null) {
            return true;
        }

        helper = new TurboHelper(service, true);
        helper.queue(attack.getLeft());
        results = helper.waitFor();
        if (results.get(0).getResponseTime() + 3000 > pauseReq.getResponseTime()) {
            return true;
        }

        // repeat for confirmation
        helper = new TurboHelper(service, true);
        helper.queue(attack.getLeft(), attack.getRight(), 4000);
        if (helper.waitFor().get(0).failed()) {
            return true;
        }

        report("H1-timetunnel v4: "+pauseReq.getResponseTime() +" vs "+results.get(0).getResponseTime(), "", pauseReq);
        return false;
    }

}
