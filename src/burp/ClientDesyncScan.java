package burp;

import java.util.HashMap;
import java.util.List;

public class ClientDesyncScan  extends Scan {

    ClientDesyncScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {

        if (service.getHost().contains(".acss.att.com")) {
            return null;
        }

        final String TRIGGER = "FOO BAR AAH\r\n\r\n";
        byte[] base = Utilities.setMethod(baseReq, "POST");
        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(TRIGGER.length()));
        base = Utilities.addOrReplaceHeader(base, "Content-Type", "text/plain");

        byte[] attack = Utilities.setBody(base, TRIGGER);
        Resp resp = request(service, attack, 0, true);
        byte[] nestedRespBytes = burp.Utilities.getNestedResponse(resp.getReq().getResponse());
        if (nestedRespBytes == null) {
            return null;
        }
        report("Client-side desync", "", resp);

        return null;
    }
}
