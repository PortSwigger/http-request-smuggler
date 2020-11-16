package burp;

import java.util.HashMap;

public class HTTP2Scan extends SmuggleScanBox implements IScannerCheck {

    HTTP2Scan(String name) {
        super(name);
    }

    public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
        if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getHost())) {
            return false;
        }

        original = setupRequest(original);
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "chunked");
        original = Utilities.setHeader(original, "Connection", "close");

        byte[] syncedReq = makeChunked(original, 0, 0, config, false);
        Resp syncedResp = request(service, syncedReq);
        if (syncedResp.failed() || (Utilities.globalSettings.getBoolean("only report exploitable") && (syncedResp.getStatus() == 400 || syncedResp.getStatus() == 501))) {
            Utilities.log("Timeout on first request. Aborting.");
            return false;
        }

        if (!Utilities.containsBytes(syncedResp.getReq().getResponse(), "HTTP/2 ".getBytes())) {
            BurpExtender.hostsToSkip.put(service.getHost(), true);
            return false;
        }

        byte[] attackReq = makeChunked(original, 0, 10, config, false);
        Resp attack = request(service, attackReq);
        if (attack.failed() && !request(service, syncedReq).failed() && !request(service, syncedReq).failed() && request(service, attackReq).failed()) {
            report("HTTP/2 TE desync v6", ".", syncedResp, attack);
            ChunkContentScan.sendPoc(original, service, true, config);
            return true;
        }

//        syncedReq = makeChunked(original, 0, 0, config, false);
//        syncedReq = Utilities.replace(syncedReq, "Transfer-Encoding", "noTranfer-Encoding");
//        syncedResp = request(service, syncedReq);
//
//        attackReq = makeChunked(original, 10, 0, config, false);
//        attackReq = Utilities.replace(attackReq, "Transfer-Encoding", "noTranfer-Encoding");
//        attack = request(service, attackReq);
//        if (attack.failed() && !request(service, syncedReq).failed() && !request(service, syncedReq).failed() && request(service, attackReq).failed()) {
//            byte[] attackConfReq = makeChunked(original, -5, 0, config, false);
//            attackConfReq = Utilities.replace(attackConfReq, "Transfer-Encoding", "noTranfer-Encoding");
//            Resp attackConf = request(service, attackConfReq);
//            if (attackConf.getStatus() == syncedResp.getStatus()) {
//                report("HTTP/2 CL desync v2", ".", syncedResp, attackConf, attack);
//            }
//            return true;
//        }

       return false;
    }
}