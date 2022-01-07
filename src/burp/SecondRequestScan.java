package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import static burp.Utilities.*;

public class SecondRequestScan extends Scan {

    SecondRequestScan(String name) {
        super(name);
        //scanSettings.importSettings(DesyncBox.h1Permutations);
        //scanSettings.importSettings(DesyncBox.h1Settings);
    }

    public List<IScanIssue> doScan(byte[] original, IHttpService service) {
        dnsScan(original, service);
//        statusScan(original, service);
//        reflectScan(original, service);
//        sslScan(original, service);
        return null;
    }

    public List<IScanIssue> dnsScan(byte[] base, IHttpService service) {
        String badPing = BasicCollab.getPayload();
        String nestedPing = BasicCollab.getPayload();

        TurboHelper helper = new TurboHelper(service, true);
        Resp prep = helper.blockingRequest(base);
        if (prep.failed()) {
            helper.waitFor();
            return null;
        }
        Resp second = helper.blockingRequest(Utilities.addOrReplaceHeader(base, "Host", nestedPing));
        helper.waitFor();

        int connections = helper.getConnectionCount();
//        if (helper.getConnectionCount() > 1) {
//            return null;
//        }

        if (!BasicCollab.checkPayload(nestedPing)) {
            return null;
        }

        helper = new TurboHelper(service, true);
        Resp first = helper.blockingRequest(Utilities.addOrReplaceHeader(base, "Host", badPing));
        helper.waitFor();
        if (BasicCollab.checkPayload(badPing)) {
            return null;
        }

        report("Suss ping: "+connections, "", base, first, second);
        return null;
    }

    public List<IScanIssue> h2Contamination(byte[] base, IHttpService service) {
        TurboHelper helper = new TurboHelper(service, true);
        Resp baseFirst = helper.blockingRequest(base);

        HashSet<String> domains = ((ThreadedRequestEngine)helper.engine).getDomains();
        String altDomain = null;
        for (String domain: domains) {
            if (domain.equals(service.getHost())) {
                continue;
            }
            altDomain = domain.replace("*", "sub");
            break;
        }

        if (altDomain == null) {
            helper.waitFor();
            return null;
        }

        byte[] alt = Utilities.addOrReplaceHeader(base, "Host", altDomain);
        byte[] blah = Utils.h2request(service, alt, "x");

        return null;
    }

    public List<IScanIssue> sslScan(byte[] base, IHttpService service) {

        TurboHelper helper = new TurboHelper(service, true);
        Resp baseFirst = helper.blockingRequest(base);

        HashSet<String> domains = ((ThreadedRequestEngine)helper.engine).getDomains();
        String altDomain = null;
        for (String domain: domains) {
            if (domain.equals(service.getHost())) {
                continue;
            }
            altDomain = domain.replace("*", "sub");
            break;
        }

        if (altDomain == null) {
            helper.waitFor();
            return null;
        }

        byte[] alt = Utilities.addOrReplaceHeader(base, "Host", altDomain);
        Resp altSecond = helper.blockingRequest(alt);
        helper.waitFor();
        helper = new TurboHelper(service, true);
        Resp altFirst = helper.blockingRequest(alt);
        Resp baseSecond = helper.blockingRequest(base);
        helper.waitFor();
        if (helper.getConnectionCount() > 1) {
            return null;
        }

        Resp first;
        Resp second;
        byte[] prep;

        if (baseFirst.getStatus() != baseSecond.getStatus() && !baseSecond.failed()) {
            prep = alt;
            first = baseFirst;
            second = baseSecond;
        } else if (altFirst.getStatus() != altSecond.getStatus() && !altSecond.failed()) {
            prep = base;
            first = altFirst;
            second = altSecond;
        } else {
            return null;
        }

        helper = new TurboHelper(service, true);
        helper.queue(prep);
        Resp notFound = helper.blockingRequest(Utilities.setPath(second.getReq().getRequest(), "/.well-known/cake"));
        helper.waitFor();

        if (notFound.getStatus() == second.getStatus()) {
            return null;
        }

        report("Connection contamination", "", base, first, second);

        return null;
    }

    public List<IScanIssue> statusScan(byte[] original, IHttpService service) {
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        original = Utilities.addOrReplaceHeader(original, "X-Hostname", service.getHost());
        original = Utilities.addOrReplaceHeader(original, "Connection", "keep-alive");

        String canary = Utilities.generateCanary();
        String newHost = canary + "." + service.getHost();
        final String TRIGGER = helpers.bytesToString(Utilities.addOrReplaceHeader(original, "Host", newHost));

        TurboHelper helper = new TurboHelper(service, true);
        helper.queue(helpers.bytesToString(original));
        helper.queue(TRIGGER);
        List<Resp> results = helper.waitFor();
        if (results.size() < 2) {
            return null;
        }

//        if ("null".equals(new String(results.get(0).getReq().getResponse()))) {
//            return null;
//        }

        if (helper.getConnectionCount() > 1) {
            return null;
        }

        Resp indirect = results.get(1);
        helper = new TurboHelper(service, true);
        helper.queue(TRIGGER);
        results = helper.waitFor();
        Resp direct = results.get(0);

        int indirectCode = indirect.getStatus();
        int directCode = direct.getStatus();
        if (indirectCode == directCode) {
            return null;
        }
        helper = new TurboHelper(service, true);
        helper.queue(helpers.bytesToString(original));
        helper.queue(Utilities.setPath(helpers.stringToBytes(TRIGGER), "/.well-known/cake"));
        results = helper.waitFor();
        Resp indirect404 = results.get(1);
        int indirect404code = indirect404.getStatus();
        if (indirect404code == indirectCode) {
            return null;
        }

        String title;
        if (Utilities.contains(indirect, canary) || Utilities.contains(indirect404, canary) ) {
            title = "Second-request code diff w/reflection"+directCode+"/"+indirectCode;
        } else {
            title = "Second-request code diff: "+directCode+"/"+indirectCode;//+naturalNested;
        }
        report(title, "", original, direct, indirect, indirect404);

        return null;
    }

    private List<IScanIssue> reflectScan(byte[] original, IHttpService service) {

        if(service.getHost().contains(".acss.att.com")) {
            return null;
        }

        String canary = Utilities.generateCanary();
        String newHost = canary + "."+service.getHost();

        //original = setupRequest(original);
        original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
        //original = Utilities.addOrReplaceHeader(original, "X-Hostname", service.getHost());
        original = Utilities.addOrReplaceHeader(original, "Connection", "keep-alive");

        //final String TRIGGER = helpers.bytesToString(Utilities.setPath(original, "https://s6zkw25wq1zfn80sp48bqqbshjneb3.psres.net/"));
        final String TRIGGER = helpers.bytesToString(Utilities.addOrReplaceHeader(original, "Host", newHost));

        Resp bad = request(service, TRIGGER.getBytes(), 0, true);
        if (Utilities.contains(bad, "Incapsula incident ID")) {
            return null;
        }

        TurboHelper helper = new TurboHelper(service, true);
        helper.queue(new String(original));
        helper.queue(TRIGGER);
        List<Resp> results = helper.waitFor();
        if (results.size() < 2) {
            return null;
        }

        if ("null".equals(new String(results.get(0).getReq().getResponse()))) {
            return null;
        }

        if (helper.getConnectionCount() > 1) {
            //report("Keepalive-fail"+nonNestedCode+":"+nestedRespCode," ", resp, bad, results.get(0), results.get(1));
            return null;
        }

        int badMatches = Utilities.countMatches(bad, canary);
        Resp secondResp = results.get(1);
        int secondMatches = Utilities.countMatches(secondResp, canary);
        if (badMatches == secondMatches) {
            return null;
        }

        helper = new TurboHelper(service, true);
        helper.queue(TRIGGER);
        results = helper.waitFor();
        badMatches = Utilities.countMatches(results.get(0), canary); // hopefully won't NPE
        if (secondMatches == badMatches) {
            return null;
        }

        helper = new TurboHelper(service, true);
        helper.blockingRequest(original);
        Resp notFound = helper.blockingRequest(Utilities.setPath(secondResp.getReq().getRequest(), "/.well-known/cake"));
        helper.waitFor();

        String title = "Second-request reflection: "+badMatches+"/"+secondMatches;
        int notFoundMatches = Utilities.countMatches(notFound, canary);
        if (notFound.getStatus() != secondResp.getStatus() || secondMatches != notFoundMatches) {
            title += " |good";
        }

        // todo add repeats to prevent random-code FPs

        report(title, "", original, results.get(0), secondResp, notFound);
        return null;
    }

    static Resp desyncRequest(IHttpService service, byte[] req, int maxRetries, boolean forceHTTP1, boolean nestRequest) {
        if (!nestRequest) {
            return request(service, req, maxRetries, forceHTTP1);
        }
        long startTime = System.currentTimeMillis();
        TurboHelper helper = new TurboHelper(service, true);
        helper.queue("GET / HTTP/1.1\r\nHost: "+service.getHost()+"\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36\r\nAccept: */*\r\n\r\n");
        helper.queue(ChunkContentScan.bypassContentLengthFix(req));
        List<Resp> results = helper.waitFor();
        if (results.size() < 2 || results.get(0).failed() || helper.getConnectionCount() > 1) {
            return new Resp(new Req(req, null, service), startTime);
        }

        return results.get(1);
    }

}
