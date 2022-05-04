package burp;

import java.util.List;

public class HTTP2FakePseudo extends Scan {
    HTTP2FakePseudo(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {

        //String collab = Utilities.globalSettings.getString("collab-domain");
        //String reflect = collab.split("\\.")[0];
        byte[] attack;
        Resp resp = null;

        String canary = "mclmkdz";
        //attack = Utilities.addOrReplaceHeader(baseReq, ":path", Utilities.getPathFromRequest(baseReq)+"\r\nx: x\r\n :path: /"+canary);
        attack = Utilities.addOrReplaceHeader(baseReq, "x", "x\r\n:path : /"+canary);

        resp = HTTP2Scan.h2request(service, attack);
        if (Utilities.contains(resp, canary)) {
            report("Fake pseudo reflection", "", resp);
        }
        return null;
    }
}
