package burp;

import java.util.List;

public class HTTP2Scheme extends Scan {
    HTTP2Scheme(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {

        String collab = Utilities.globalSettings.getString("collab-domain");
        String reflect = collab.split("\\.")[0];
        byte[] attack;
        Resp resp = null;

        if (service.getHost().contains(".yahoo") || service.getHost().contains(".aol")) {
            return null;
        }

        String canary = "mclmkdz";
        attack = Utilities.addOrReplaceHeader(baseReq, ":scheme", "http://"+service.getHost()+"/"+canary+"?");
        resp = HTTP2Scan.h2request(service, attack);
        if (Utilities.contains(resp, canary)) {
            report("Scheme path reflection v2", "", resp);
        }

//        attack = Utilities.addOrReplaceHeader(baseReq, ":scheme", "https://"+collab+"/");
//        attack = Utilities.addOrReplaceHeader(attack, ":authority", collab);
//        resp = request(service, attack);
//
//        attack = Utilities.addOrReplaceHeader(baseReq, ":scheme", "https://"+collab+"/");
//        attack = Utilities.addOrReplaceHeader(attack, "Host", collab);
//        resp = request(service, attack);
//
//        attack = Utilities.addOrReplaceHeader(baseReq, ":scheme", collab);
//        resp = request(service, attack);


//
//
        attack = Utilities.addOrReplaceHeader(baseReq, ":scheme", "http://"+collab+"/");
        resp = HTTP2Scan.h2request(service, attack);
        if (Utilities.contains(resp, reflect)) {
            report("Scheme domain reflection v2", "", resp);
        }
//
//
//        attack = Utilities.addOrReplaceHeader(baseReq, ":scheme", canary);
//        resp = request(service, attack);
//        if (Utilities.contains(resp, canary)) {
//            report("Scheme reflection", "", resp);
//        }
//
//        attack = Utilities.addOrReplaceHeader(baseReq, ":scheme", "file");
//        attack = Utilities.setPath(attack, "/etc/passwd");
//        resp = request(service, attack);
//        if (Utilities.contains(resp, ":root:")) {
//            report("File theft bahahahaha", "", resp);
//        }

        return null;
    }
}
