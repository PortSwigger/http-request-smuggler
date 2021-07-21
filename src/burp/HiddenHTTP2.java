package burp;

import java.util.List;

public class HiddenHTTP2 extends Scan {
    HiddenHTTP2(String name) {
        super(name);
    }


    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse) {

        if (Utilities.containsBytes(baseRequestResponse.getRequest(), "HTTP/2\r\n".getBytes())) {
            return null;
        }

        if (Utilities.containsBytes(baseRequestResponse.getResponse(), "HTTP/2\r\n".getBytes())) {
            return null;
        }

        IHttpService service = baseRequestResponse.getHttpService();
        Utilities.callbacks.makeHttpRequest(service, baseRequestResponse.getRequest());
        Resp noForce = request(service, baseRequestResponse.getRequest());

        if (noForce.failed() || Utilities.contains(noForce, "HTTP/2\r\n")) {
            //Utilities.callbacks.addToSiteMap(noForce.getReq());
            BurpExtender.hostsToSkip.put(service.getHost(), true);
            return null;
        }

        Resp freshBase = HTTP2Scan.h2request(service, baseRequestResponse.getRequest());
        if (freshBase.failed() || !Utilities.contains(freshBase, "HTTP/2")) {
            BurpExtender.hostsToSkip.put(service.getHost(), true);
            return null;
        }

        if (Utilities.containsBytes(noForce.getReq().getResponse(), "HTTP/1.1 ".getBytes()) && !Utilities.containsBytes(noForce.getReq().getResponse(), "HTTP/2 ".getBytes())) {
            report("Hidden-HTTP2", "", freshBase, noForce);
            Utilities.callbacks.addToSiteMap(freshBase.getReq());
        }

        return null;
    }

}
