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
        if (!syncedResp.failed()) {
            if (!Utilities.containsBytes(syncedResp.getReq().getResponse(), "HTTP/2 ".getBytes())) {
                BurpExtender.hostsToSkip.put(service.getHost(), true);
                return false;
            }

            byte[] attackReq = makeChunked(original, 0, 10, config, false);
            Resp attack = request(service, attackReq);
            if (attack.timedOut() && !request(service, syncedReq).timedOut() && !request(service, syncedReq).timedOut() && request(service, attackReq).timedOut()) {
                report("HTTP/2 TE desync v8", ".", syncedResp, attack);
                ChunkContentScan.sendPoc(original, service, true, config);
                return true;
            }
        }

        // dodgy but worthwhile as HEAD-detection is a bit unreliable
        syncedReq = makeChunked(original, -1, 0, config, false);
        syncedReq = Utilities.replace(syncedReq, "Transfer-Encoding", "nope");
        syncedResp = request(service, syncedReq);

        // if they reject this they probably just don't like a content-type mismatch
        if (!syncedResp.failed()) {
            byte[] attackReq = makeChunked(original, 10, 0, config, false);
            attackReq = Utilities.replace(attackReq, "Transfer-Encoding", "nope");
            Resp attack = request(service, attackReq);
            if (attack.timedOut() && !request(service, syncedReq).timedOut() && !request(service, syncedReq).timedOut() && request(service, attackReq).timedOut()) {
                report("HTTP/2 CL desync v3", ".", syncedResp, attack);
                return true;
            }
        }

       return false;
    }
}