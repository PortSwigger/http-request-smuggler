package burp;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class ImplicitZeroScan extends SmuggleScanBox {
    HashMap<String, Pair<String,String>> recordedGasget = new HashMap<>();

    ImplicitZeroScan(String name) {
        super(name);
        scanSettings.importSettings(DesyncBox.sharedSettings);
        scanSettings.importSettings(DesyncBox.sharedPermutations);
        // todo add h1 and h2 permutations
    }

    @Override
    // fixme before attempting any major work, clean this up!
    public boolean doConfiguredScan(byte[] baseReq, IHttpService service, HashMap<String, Boolean> config) {

        Utilities.supportsHTTP2 = true;

        boolean h2 = Utilities.isHTTP2(baseReq);

        baseReq = Utilities.addCacheBuster(baseReq, null);

        byte[] req = SmuggleScanBox.setupRequest(baseReq);
        req = Utilities.replaceFirst(req, "Content-Type: ", "X-Content-Type: ");

        if (h2) {
            req = Utilities.replaceFirst(req, " HTTP/2\r\n", " HTTP/1.1\r\n");
            req = Utilities.replaceFirst(req, "Content-Length: ", "X-CL: ");
            req = Utilities.replaceFirst(req, "Connection: ", "X-Connection: ");
        } else {
            req = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");
        }

        // skip permutations that don't have any effect
        String technique = config.keySet().iterator().next();
        if (null == DesyncBox.applyDesync(req, "Content-Length", technique)) {
            Utils.out("Skipping permutation: "+technique);
            return false;
        }

        Utilities.out("Technique: "+technique);

        final String justBodyReflectionCanary = "YzBqv";
        String smuggle = String.format("GET %s HTTP/1.1\r\nX-"+justBodyReflectionCanary+": ", Utilities.getPathFromRequest(baseReq));
        req = Utilities.fixContentLength(Utilities.setBody(req, smuggle));
        //req = Utilities.addOrReplaceHeader(req, "Content-Length", ""+smuggle.length());
        //req = Utilities.addOrReplaceHeader(req, "Connection", "Content-Length");

        Resp untampered = request(service, baseReq);
        Pair<String, String> gadget = selectGadget(service, req, untampered);

        if (gadget == null) {
            return false;
        }

        int attempts = 9;

        for (int i=0; i<attempts; i++) {
            smuggle = String.format("%s HTTP/1.1\r\nX-"+justBodyReflectionCanary+": ", gadget.getLeft());
            byte[] attack = Utilities.setBody(req, smuggle);
            attack = Utilities.fixContentLength(attack);
            attack = DesyncBox.applyDesync(attack, "Content-Length", technique);

            Resp resp = request(service, attack);
            if (resp.failed()) {
                return false;
            }

            if (Utilities.contains(resp, gadget.getRight())) {
                if ("wrtztrw".equals(gadget.getRight()) && Utilities.contains(resp, justBodyReflectionCanary) ) {
                    return false;
                }

                report("CL.0 desync: "+gadget.getLeft(), "HTTP Request Smuggler repeatedly issued the attached request. After "+i+ " attempts, it got a response that appears to have been poisoned by the body of the previous request. For further details and information on remediation, please refer to https://portswigger.net/research/browser-powered-desync-attacks", baseReq, resp);
                return true;
            }
        }

        return false;
    }

    Pair<String, String> selectGadget(IHttpService service, byte[] req, Resp untampered) {
        String host = service.getHost();
        if (recordedGasget.containsKey(host)) {
            return recordedGasget.get(host);
        }


        Resp baseResp = request(service, req);
        String basePath = Utilities.getMethod(req)+ " "+Utilities.getPathFromRequest(req);
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


