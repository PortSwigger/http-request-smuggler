package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

public class ImplicitZeroScan extends SmuggleScanBox {
    HashMap<String, Mapping> recordedGadget = new HashMap<>();
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
        if (DesyncBox.h1Permutations.contains(technique)) {
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

        req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
        if (h2 && !forceHTTP1) {
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

        Mapping gadget = selectGadget(service, req, baseReq);

        if (gadget == null) {
            //Utilities.out("No viable gadgets, skipping endpoint");
            gadget = new Mapping("GET / HTTP/2.2", "505 HTTP", true);
            //return false;
        }

        int attempts = 9;
        short status = 0;
        boolean badFirstStatus = false;
        Resp lastResp = null;

        for (int i=0; i<attempts; i++) {
            smuggle = String.format("%s\r\nX-"+justBodyReflectionCanary+": ", gadget.payload);
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

            if (gadget.worked(resp)) {
                if ("wrtztrw".equals(gadget.payload) && Utilities.contains(resp, justBodyReflectionCanary) ) {
                    return false;
                }

                // this gadget will get FPs on this endpoint
                if (i == 0) {
                    return false;
                }

                report("CL.0 desync: "+technique+"|"+gadget.payload, "HTTP Request Smuggler repeatedly issued the attached request. After "+i+ " attempts, it got a response that appears to have been poisoned by the body of the previous request. For further details and information on remediation, please refer to https://portswigger.net/research/browser-powered-desync-attacks", baseReq, lastResp, resp);
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

    Mapping selectGadget(IHttpService service, byte[] req, byte[] base) {
        String host = service.getHost();
        if (recordedGadget.containsKey(host)) {
            return recordedGadget.get(host);
        }

        Resp untampered = request(service, base);
        Resp baseResp = request(service, req);
        String basePath = Utilities.getMethod(req)+ " "+Utilities.getPathFromRequest(req) + " HTTP/1.1";
        ArrayList<Mapping> mappings = new ArrayList<>();
        // remember the response will come from the back-end, so don't use malformed requests
//        String collab = Utilities.globalSettings.getString("collab-domain");
//        return new ImmutablePair<>("GET https://"+collab+"/?"+service.getHost(), collab);

        mappings.add(new Mapping("GET /robots.txt HTTP/1.1", "llow:"));
        mappings.add(new Mapping("GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1", "wrtztrw"));
        mappings.add(new Mapping("GET /favicon.ico HTTP/1.1", "Content-Type: image/", true));
        mappings.add(new Mapping("GET /sitemap.xml HTTP/1.1", "Content-Type: application/xml", true));
        mappings.add(new Mapping("TRACE / HTTP/1.1", "405 Method Not Allowed", true));
        mappings.add(new Mapping("GET / HTTP/2.2", "505 HTTP", true));
        //mappings.add(new ImmutablePair<>("X /", "405 Method Not Allowed"));
        //mappings.add(new ImmutablePair<>("GET /../", "400 Bad Request"));

        // fixme something is wrong in here
        for (Mapping known: mappings) {
            String knownPath = known.payload;
            String knownContent = known.lookFor;
            if (knownPath.equals(basePath)) {
                continue;
            }

            if (Utilities.contains(baseResp, knownContent) || Utilities.contains(untampered, knownContent)) {
                continue;
            }

            // fixme fails when request-line ends in HTTP/2
            byte[] attack = Utilities.replaceFirst(req, basePath, knownPath);
            attack = Utilities.setBody(attack, ""); // required to avoid poisoning the socket during gadget detection
            attack = Utilities.fixContentLength(attack);

            Resp resp = request(service, attack);
            if (resp.failed()) {
                continue;
            }

            if (!known.worked(resp)) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {

                }
                continue;
            }

            recordedGadget.put(host, known);
            return known;
        }

        recordedGadget.put(host, null);
        return null;
    }

}

class Mapping {
    String payload = "";
    String lookFor = "";
    boolean onlyLookInHeader = false;

    public Mapping(String payload, String lookFor, boolean onlyLookInHeader) {
        this.payload = payload;
        this.lookFor = lookFor;
        this.onlyLookInHeader = onlyLookInHeader;
    }

    public Mapping(String payload, String lookFor) {
        this.payload = payload;
        this.lookFor = lookFor;
    }

    public boolean worked(Resp resp) {
        byte[] contentToCheck = resp.getResponse();
        if (this.onlyLookInHeader) {
            contentToCheck = Utilities.getHeaders(contentToCheck).getBytes();
        }

        return Utilities.containsBytes(contentToCheck, lookFor.getBytes());
    }
}

