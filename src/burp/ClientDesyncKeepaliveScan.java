package burp;

import java.util.List;

public class ClientDesyncKeepaliveScan extends Scan {

    ClientDesyncKeepaliveScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        String TRIGGER = "G";
        byte[] base = Utilities.setMethod(baseReq, "POST");
        base = Utilities.addOrReplaceHeader(base, "Content-Length", String.valueOf(TRIGGER.length()));
        base = Utilities.addOrReplaceHeader(base, "Content-Type", "text/plain");

        byte[] attack = Utilities.setBody(base, TRIGGER);
        SmuggleHelper helper = new SmuggleHelper(service, true);

        helper.queue(new String(attack));
        helper.queue(new String(attack));
        List<Resp> results = helper.waitFor();
        if (results.size() < 2) {
            return null;
        }

        Resp first = results.get(0);
        Resp second = results.get(1);

        if (first.failed() || second.failed()) {
            return null;
        }

        if (helper.getConnectionCount() > 1) {
            return null;
        }

        if (first.getStatus() == second.getStatus()) {
            return null;
        }

        report("Client-side desync (keepalive): "+first.getStatus()+"|"+second.getStatus(), "", first, second);

        return null;

    }
}