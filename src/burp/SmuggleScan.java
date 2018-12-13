package burp;

import java.util.List;

public class SmuggleScan extends Scan implements IScannerCheck  {

    Response buildAttack(Response basereq) {
        byte[] req = basereq.getReq().getRequest();
        byte[] badMethodIfChunked = Utilities.setBody(req, "0\r\n\r\nG"+Utilities.helpers.bytesToString(req));

        badMethodIfChunked = Utilities.setHeader(badMethodIfChunked, "Connection", "keep-alive");
        badMethodIfChunked = Utilities.setHeader(badMethodIfChunked, "Content-Length", "6");

        return new Response(new Request(badMethodIfChunked, null, basereq.getReq().getHttpService()));
    }

    public List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        // todo handle non-zero bodies
        //int bodySize = baseReq.length - Utilities.getBodyStart(baseReq);
        //Utilities.out(""+bodySize);
        //Utilities.getBody(baseReq);

        baseReq = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "chunked");
        baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Length", "5");
        baseReq = Utilities.setBody(baseReq, "0\r\n\r\n");
        Response syncedResp = request(service, baseReq);
        if (syncedResp.timedOut()) {
            Utilities.out("Timeout on first request. Aborting.");
            return null;
        }

        Response suggestedProbe = buildAttack(syncedResp);

        byte[] reverseLength = Utilities.setHeader(baseReq, "Content-Length", "4");
        Response truncatedChunk = request(service, reverseLength);
        if (truncatedChunk.timedOut()) {
            Utilities.out("Reporting reverse timeout technique worked");
            report("Request smuggling v1-b", "Status:timeout", syncedResp, truncatedChunk, suggestedProbe, buildAttack(truncatedChunk));
            //return null;
        }
        else {
            byte[] dualChunkTruncate = Utilities.addOrReplaceHeader(reverseLength, "Transfer-encoding", "cow");
            Response truncatedDualChunk = request(service, dualChunkTruncate);
            if (truncatedDualChunk.timedOut()) {
                Utilities.out("Reverse timeout technique with dual TE header worked");
                report("Request smuggling v2", "Status:timeout", syncedResp, truncatedDualChunk);
            }
        }

        byte[] badLength = Utilities.setHeader(baseReq, "Content-Length", "6");
        Response badLengthResp = request(service, badLength);
        if (!badLengthResp.timedOut() && badLengthResp.getInfo().getStatusCode() == syncedResp.getInfo().getStatusCode()) {
            Utilities.out("Overlong content length didn't cause a timeout or code-change. Aborting.");
            return null;
        }

        byte[] badChunk = Utilities.setBody(baseReq, "Z\r\n\r\n");
        Response badChunkResp = request(service, badChunk);
        if (badChunkResp.timedOut()) {
            Utilities.out("Bad chunk attack timed out. Aborting.");
            return null;
        }

        if (badChunkResp.getInfo().getStatusCode() == syncedResp.getInfo().getStatusCode()) {
            Utilities.out("Invalid chunk probe caused a timeout. Attempting chunk timeout instead.");

            byte[] timeoutChunk = Utilities.setBody(baseReq, "1\r\n\r\n");
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

