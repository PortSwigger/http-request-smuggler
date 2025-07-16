package burp;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class ImplicitZeroScan extends SmuggleScanBox {
    HashMap<String, Pair<String,String>> recordedGasget = new HashMap<>();
    HashSet<String> reportedStatus = new HashSet<>();

    ImplicitZeroScan(String name) {
        super(name);
        scanSettings.register("report potential 0.CL", true);
        scanSettings.importSettings(DesyncBox.sharedSettings);
        scanSettings.importSettings(DesyncBox.sharedPermutations);
        scanSettings.importSettings(DesyncBox.clPermutations);
        scanSettings.importSettings(DesyncBox.h2Permutations);
        scanSettings.importSettings(DesyncBox.h1Permutations);
    }

    @Override
    // fixme before attempting any major work, clean this up!
    public boolean doConfiguredScan(byte[] baseReq, IHttpService service, HashMap<String, Boolean> config) {

        Utilities.supportsHTTP2 = true;

        boolean h2 = Utilities.isHTTP2(baseReq);

        baseReq = Utilities.addCacheBuster(baseReq, null);

        byte[] req = SmuggleScanBox.setupRequest(baseReq);
        //req = Utilities.replaceFirst(req, "Content-Type: ", "X-Content-Type: ");

        // skip permutations that don't have any effect
        String technique = config.keySet().iterator().next();
        if (null == DesyncBox.applyDesync(req, "Content-Length", technique)) {
            //Utils.out("Skipping permutation: "+technique);
            return false;
        }

        boolean forceHTTP1 = false;
        boolean forceHTTP2 = false;
        if (DesyncBox.h1Permutations.contains(technique) || true) {
            forceHTTP1 = true;
        } else if (DesyncBox.h2Permutations.contains(technique)) {
            if (!h2) {
                Resp h2test = HTTP2Scan.h2request(service, baseReq);
                if (h2test.failed() || !Utilities.containsBytes(h2test.getReq().getResponse(), "HTTP/2".getBytes())) {
                    return false;
                }
                h2 = true;
            }
            forceHTTP2 = true;
        }

        if (h2 && !forceHTTP1) {
            req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
            //req = Utilities.replaceFirst(req, "Content-Length: ", "X-CL: ");
            req = Utilities.replaceFirst(req, "Connection: ", "X-Connection: ");
        } else {
            req = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");
        }

        final String justBodyReflectionCanary = "YzBqv";
        String smuggle = String.format("GET %s HTTP/1.1\r\nX-"+justBodyReflectionCanary+": ", Utilities.getPathFromRequest(baseReq));
        req = Utilities.fixContentLength(Utilities.setBody(req, smuggle));
        //req = Utilities.addOrReplaceHeader(req, "Content-Length", ""+smuggle.length());
        //req = Utilities.addOrReplaceHeader(req, "Connection", "Content-Length");

        Pair<String, String> gadget = selectGadget(service, req, baseReq);

        if (gadget == null) {
            return false;
        }

        int attempts = 9;
        short status = 0;
        boolean badFirstStatus = false;
        Resp lastResp = null;

        for (int i=0; i<attempts; i++) {
            smuggle = String.format("%s\r\nX-"+justBodyReflectionCanary+": ", gadget.getLeft());
            byte[] attack = Utilities.setBody(req, smuggle);
            attack = Utilities.fixContentLength(attack);
            attack = DesyncBox.applyDesync(attack, "Content-Length", technique);

            Resp resp;
            if (forceHTTP2) {
                resp = HTTP2Scan.h2request(service, attack, true);
            } else {
                resp = request(service, attack, 0, forceHTTP1);
            }

            if (resp.failed()) {
                return false;
            }

            if (Utilities.contains(resp, gadget.getRight())) {
                if ("wrtztrw".equals(gadget.getRight()) && Utilities.contains(resp, justBodyReflectionCanary) ) {
                    return false;
                }

                // this gadget will get FPs on this endpoint
                if (i == 0) {
                    return false;
                }

                report("CL.0 desync: "+technique+"|"+gadget.getLeft(), "HTTP Request Smuggler repeatedly issued the attached request. After "+i+ " attempts, it got a response that appears to have been poisoned by the body of the previous request. For further details and information on remediation, please refer to https://portswigger.net/research/browser-powered-desync-attacks", baseReq, lastResp, resp);
                return true;
            }

            if (i == 0) {
                badFirstStatus = (resp.getStatus() == 400);
            } else if (Utilities.globalSettings.getBoolean("report potential 0.CL") && !badFirstStatus && resp.getStatus() == 400 && status != 400 && !reportedStatus.contains(service.getHost())) {
                reportedStatus.add(service.getHost());
                byte[] fakeAttack = Utilities.setBody(req, " ");
                fakeAttack = Utilities.fixContentLength(fakeAttack);
                fakeAttack = DesyncBox.applyDesync(fakeAttack, "Content-Length", technique);
                boolean worked = true;
                for (int k=0; k<30; k++) {
                    Resp resp2;
                    if (forceHTTP2) {
                        resp2 = HTTP2Scan.h2request(service, fakeAttack, true);
                    } else {
                        resp2 = request(service, fakeAttack, 0, forceHTTP1);
                    }
                    if (resp2.failed() || resp2.getStatus() == 400) {
                        worked = false;
                        break;
                    }
                }
                if (worked) {
                    report("Potential 0.CL: " + technique + "| 400/" + status, i + " attempts. Refer to https://portswigger.net/research/http1-must-die", baseReq, lastResp, resp);
                }
            }

            status = resp.getStatus();
            lastResp = resp;
        }

        return false;
    }

    Pair<String, String> selectGadget(IHttpService service, byte[] req, byte[] base) {
        String host = service.getHost();
        if (recordedGasget.containsKey(host)) {
            return recordedGasget.get(host);
        }

        Resp untampered = request(service, base);
        Resp baseResp = request(service, req);
        String basePath = Utilities.getMethod(req)+ " "+Utilities.getPathFromRequest(req) + " HTTP/1.1";
        ArrayList<Pair<String, String>> mappings = new ArrayList<>();
        // remember the response will come from the back-end, so don't use malformed requests
//        String collab = Utilities.globalSettings.getString("collab-domain");
//        return new ImmutablePair<>("GET https://"+collab+"/?"+service.getHost(), collab);

        mappings.add(new ImmutablePair<>("GET /robots.txt HTTP/1.1", "llow:"));
        mappings.add(new ImmutablePair<>("GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1", "wrtztrw"));
        mappings.add(new ImmutablePair<>("GET /favicon.ico HTTP/1.1", "Content-Type: image/"));
        mappings.add(new ImmutablePair<>("GET /sitemap.xml HTTP/1.1", "Content-Type: application/xml"));
        mappings.add(new ImmutablePair<>("TRACE / HTTP/1.1", "405 Method Not Allowed"));
        mappings.add(new ImmutablePair<>("GET / HTTP/2.2", "505 HTTP"));
        //mappings.add(new ImmutablePair<>("X /", "405 Method Not Allowed"));
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

            byte[] attack = Utilities.replaceFirst(req, basePath, knownPath);
            attack = Utilities.setBody(attack, ""); // required to avoid poisoning the socket during gadget detection
            attack = Utilities.fixContentLength(attack);

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

            recordedGasget.put(host, known);
            return known;
        }

        recordedGasget.put(host, null);
        return null;
    }

}


