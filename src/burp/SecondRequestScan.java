package burp;

import java.util.HashMap;
import java.util.List;

import static burp.Utilities.getPathFromRequest;

public class SecondRequestScan extends SmuggleScanBox implements IScannerCheck {

    SecondRequestScan(String name) {
        super(name);
        scanSettings.importSettings(DesyncBox.h1Permutations);
        scanSettings.importSettings(DesyncBox.h1Settings);
    }

    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
        if (!config.containsKey("vanilla")/* && !config.containsKey("space1") && !config.containsKey("connection")*/) {
            return false;
        }

        if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getHost())) {
            return false;
        }

        if(service.getHost().contains(".acss.att.com")) {
            return false;
        }

        original = setupRequest(original);
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.addOrReplaceHeader(original, "Connection", "keep-alive");

        final String TRIGGER = "FOO BAR AAH\r\n\r\n";

        Resp bad = request(service, TRIGGER.getBytes(), 0, true);
        String nonNestedCode = getPathFromRequest(bad.getReq().getResponse());

        SmuggleHelper helper = new SmuggleHelper(service, true);
        helper.queue(new String(original));
        helper.queue(TRIGGER);
        List<Resp> results = helper.waitFor();
        if (results.size() < 2) {
            return false;
        }

        if ("null".equals(new String(results.get(0).getReq().getResponse()))) {
            return false;
        }

        if (helper.getConnectionCount() > 1) {
            //report("Keepalive-fail"+nonNestedCode+":"+nestedRespCode," ", resp, bad, results.get(0), results.get(1));
            return false;
        }

        String naturalNested = String.valueOf(results.get(1).getStatus());
        if (naturalNested.equals(nonNestedCode)) {
            return false;
        }

        //if (Utilities.getHeader(results.get(0).getReq().getResponse()))

        // byte[] brokenAttackReq = Utilities.replace(attackReq, "ransfer", "zansfer");
        // byte[] brokenAttackReq = Utilities.replace(attackReq, "Content-Length", "Content-Cake");

        // todo add repeats to prevent random-code FPs
        String title = "Second-request diff: "+nonNestedCode+":"+naturalNested;
        report(title, "", bad, results.get(0), results.get(1));
        return true;
    }

}
