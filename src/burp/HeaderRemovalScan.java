package burp;

import java.util.List;

public class HeaderRemovalScan extends Scan {
    HeaderRemovalScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse) {
        byte[] baseReq = baseRequestResponse.getRequest();
        boolean FORCEHTTP1 = true;
        String CANARY = "wrtzwrrrrr";
        IHttpService service = baseRequestResponse.getHttpService();
        baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Length", "1");
        baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Type", "application/x-www-form-urlencoded");
        baseReq = Utilities.setBody(baseReq, "Host: "+CANARY);
        baseReq = Utilities.fixContentLength(baseReq);
        baseReq = Utilities.setMethod(baseReq, "POST");
        baseReq = Utilities.addOrReplaceHeader(baseReq, "Connection", "keep-alive");

        byte[] attack = Utilities.addOrReplaceHeader(baseReq, "Keep-Alive", "timeout=5, max=1000");
        //attack = Utilities.addOrReplaceHeader(attack, " Host", CANARY);

        byte[] harmless = Utilities.replaceFirst(attack, "Keep-Alive: ", "Eat-Alive: ");
        // attack = Utilities.replaceFirst(attack, "\r\n\r\n", "\n\n");
        // harmless = Utilities.replaceFirst(harmless, "\r\n\r\n", "\n\n");
        Resp harmlessResp = null;
        Resp attackResp = null;
        for (int i=0; i<5; i++ ) {
            harmlessResp = request(service, harmless, 0, FORCEHTTP1);
            if (harmlessResp.failed()) {
                return null;
            }
            attackResp = request(service, attack, 0, FORCEHTTP1);
            if (attackResp.getStatus() == harmlessResp.getStatus() && Utilities.contains(attackResp, CANARY) == Utilities.contains(harmlessResp, CANARY)) {
                return null;
            }
        }

        // final out of order follow-up to filter round-robin noise
        attackResp = request(service, attack, 0, FORCEHTTP1);
        if (attackResp.getStatus() == harmlessResp.getStatus() && Utilities.contains(attackResp, CANARY) == Utilities.contains(harmlessResp, CANARY)) {
            return null;
        }

        BulkScan.hostsToSkip.put(service.getHost(), true);
        report("Bad header removal v2", "", baseReq, harmlessResp, attackResp);
        return null;
    }

}
