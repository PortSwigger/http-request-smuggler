//package burp;
//
//import java.io.ByteArrayOutputStream;
//import java.io.IOException;
//import java.util.HashMap;
//import java.util.List;

//Test Change

//public class DualContentScan extends SmuggleScanBox implements IScannerCheck  {
//
//    DualContentScan(String name) {
//        super(name);
//        registerPermutation("pad1");
//        registerPermutation("pad2");
//        Utilities.globalSettings.registerSetting("only pad identical", true);
//    }
//
//
//    byte[] dualContent(byte[] baseReq, int offset1, int offset2, HashMap<String, Boolean> config) {
//        int contentLength = baseReq.length - Utilities.getBodyStart(baseReq); // Integer.parseInt(Utilities.getHeader(baseReq, "Content-Length"));
//
//        String off1 = String.valueOf(contentLength+offset1);
//        String off2 = String.valueOf(contentLength+offset2);
//        if (off1.equals(off2) || !Utilities.globalSettings.getBoolean("only pad identical") ) {
//            if (config.containsKey("pad1")) {
//                off1 = "0" + off1;
//            }
//            if (config.containsKey("pad2")) {
//                off2 = "0" + off2;
//            }
//        }
//
//        baseReq = Utilities.replace(baseReq, "Content-Length".getBytes(), "oldContent-Length".getBytes());
//
//        String name1 = "Content-length";
//        String name2 = "content-length";
//
//        if(config.containsKey("space1")) {
//            name1 += " ";
//        }
//        if(config.containsKey("space2")) {
//            name2 += " ";
//        }
//
//        if (config.containsKey("underscore1")) {
//            name1 = name1.replace("-", "_");
//        }
//        if (config.containsKey("underscore2")) {
//            name2 = name2.replace("-", "_");
//        }
//
//        baseReq = Utilities.addOrReplaceHeader(baseReq, name1, off1);
//        baseReq = Utilities.addOrReplaceHeader(baseReq, name2, off2);
//
//        return baseReq;
//    }
//
//    boolean doConfiguredScan(byte[] baseReq, IHttpService service, HashMap<String, Boolean> config) {
//        if (Utilities.globalSettings.getBoolean("skip vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(service.getProtocol()+service.getHost())) {
//            return false;
//        }
//
//        baseReq = setupRequest(baseReq);
//
//        IParameter notEmpty = burp.Utilities.helpers.buildParameter("notempty", "1", IParameter.PARAM_BODY);
//        baseReq = Utilities.helpers.addParameter(baseReq, notEmpty);
//
//        if (request(service, baseReq).timedOut()) {
//            return false;
//        }
//
//
//        byte[] noAttack = dualContent(baseReq, 0, 0, config);
//
//        Resp baseline = request(service, noAttack);
//        if (baseline.timedOut()) {
//            return false;
//        }
//
//        Resp firstHeader = request(service, dualContent(baseReq, 1, 0, config));
//        if (firstHeader.getStatus() == baseline.getStatus()) {
//            return false;
//        }
//
//        Resp secondHeader = request(service, dualContent(baseReq, 0, 1, config));
//        if (secondHeader.getStatus() == baseline.getStatus()) {
//            return false;
//        }
//
//        // we rely on a timeout because so many servers just reject non-matching CL
//        // it would be interesting to spot servers with different timeouts for firstHeader vs secondHeader
//        // "HTTP Error 400. The request has an invalid header name." => microsoft doesn't like dupe headers with different values
//        if (firstHeader.getStatus() == secondHeader.getStatus()) {
//            if (firstHeader.timedOut()) {
//                //report("CL-CL: x-T-T", "X:Y:Y", baseline, firstHeader, secondHeader);
//            } else {
//                return false;
//            }
//        } else {
//            if (firstHeader.timedOut() || secondHeader.timedOut()) {
//                //report("CL-CL: x-y-T", "X:Y:Z", baseline, firstHeader, secondHeader);
//            } else {
//                //report("CL-CL: x-y-z", "X:Y:Z", baseline, firstHeader, secondHeader);
//            }
//        }
//
//        report("CL-CL: worth retargeting", "meh", baseline, firstHeader, secondHeader);
//
//
//        try {
//            byte[] prefix = "G".getBytes(); // good ol' GPOST
//            ByteArrayOutputStream stream = new ByteArrayOutputStream();
//            stream.write(baseReq);
//            stream.write(prefix);
//            final byte[] attack = stream.toByteArray();
//            sendPoc("CL-CL-1", dualContent(attack, 0, -prefix.length, config), noAttack, service, config);
//            sendPoc("CL-CL-2", dualContent(attack, -prefix.length, 0, config), noAttack, service, config);
//
//        } catch (IOException e) {
//
//        }
//        BurpExtender.hostsToSkip.put(service.getProtocol()+service.getHost(), true);
//        return true;
//    }
//}