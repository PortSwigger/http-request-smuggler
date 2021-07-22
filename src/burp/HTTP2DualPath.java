package burp;

import java.util.Arrays;
import java.util.List;

public class HTTP2DualPath extends Scan {

    HTTP2DualPath(String name) {super(name);}

    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        String path = Utilities.getPathFromRequest(baseReq);
        byte[] attack;
        String canary = "asdfwrtz";

        // what if they concatenate? this will give a 404
        attack = Utilities.addOrReplaceHeader(baseReq, ":path", path+"\r\n:path: "+path);
        Resp resp = HTTP2Scan.h2request(service, attack);
        if (!resp.failed() && resp.getStatus() < 400) {
            attack = Utilities.addOrReplaceHeader(baseReq, ":path", path+"\r\n:path: /"+canary);
            Resp break1 = HTTP2Scan.h2request(service, attack);

            attack = Utilities.addOrReplaceHeader(baseReq, ":path", "/"+canary+"\r\n:path: "+path);
            Resp break2 = HTTP2Scan.h2request(service, attack);

            String detail = "";
            if (Utilities.contains(break1, canary)) {
                detail += "X";
            }
            if (Utilities.contains(break1, canary)) {
                detail += "Y";
            }

            if (resp.getStatus() == break1.getStatus() && resp.getStatus() == break2.getStatus()) {
                return null;
            }


            report("Dual path supported v2: "+resp.getStatus()+"-"+break1.getStatus()+"-"+break2.getStatus()+"|| "+detail, "", resp, break1, break2);
        }


        return null;
    }
}
