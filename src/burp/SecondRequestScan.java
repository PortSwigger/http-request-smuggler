package burp;

import java.util.HashMap;
import java.util.List;

import static burp.Utilities.getPathFromRequest;
import static burp.Utilities.helpers;

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

        if(service.getHost().contains(".acss.att.com")) {
            return false;
        }

        original = setupRequest(original);
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.addOrReplaceHeader(original, "Connection", "keep-alive");

        final String TRIGGER = helpers.bytesToString(Utilities.addOrReplaceHeader(original, "Host", "uxvmn4wyh3qhearug6zdhs2u8lee23.psres.net"));

        Resp bad = request(service, TRIGGER.getBytes(), 0, true);
        if (Utilities.contains(bad, "Incapsula incident ID")) {
            return false;
        }
        String nonNestedCode = getPathFromRequest(bad.getReq().getResponse());

        TurboHelper helper = new TurboHelper(service, true);
        helper.queue(new String(original));
        helper.queue(TRIGGER.replace("uxvmn4wyh3qhearug6zdhs2u8lee23.psres.net", "8w50mivcghpvdoq8fkyrg6187zdt1i.psres.net"));
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

        if (Utilities.countMatches(bad, "psres.net") == Utilities.countMatches(results.get(1), "psres.net")) {
            return false;
        }

//        String naturalNested = String.valueOf(results.get(1).getStatus());
//        if (naturalNested.equals(nonNestedCode)) {
//            return false;
//        }

        //if (Utilities.getHeader(results.get(0).getReq().getResponse()))

        // byte[] brokenAttackReq = Utilities.replace(attackReq, "ransfer", "zansfer");
        // byte[] brokenAttackReq = Utilities.replace(attackReq, "Content-Length", "Content-Cake");

        // todo add repeats to prevent random-code FPs
        String title = "Second-request diff ref: "+nonNestedCode;//+naturalNested;
        report(title, "", original, bad, results.get(1));
        return true;
    }

}
