package burp;

import java.util.Arrays;
import java.util.List;

public class HTTP2Method extends Scan {

    HTTP2Method(String name) {
        super(name);
        scanSettings.register("collab-domain", Utilities.generateCanary()+".burpcollaborator.net");
    }

    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        String path = Utilities.getPathFromRequest(baseReq);
        String collab = Utilities.globalSettings.getString("collab-domain");
        byte[] attack;

        if (service.getHost().contains(".yahoo") || service.getHost().contains(".aol")) {
            return null;
        }

        attack = Utilities.addOrReplaceHeader(baseReq, ":method", "GET http://"+collab+path +" HTTP/1.1");
        Resp resp = HTTP2Scan.h2request(service, attack);
        if (Utilities.contains(resp, collab)) {
            report("Method path reflection v2", "", resp);
        }

        return null;
    }
}
