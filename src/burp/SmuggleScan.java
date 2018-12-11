package burp;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SmuggleScan implements  IScannerCheck {

    private ZgrabLoader loader = null;

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }

    void setRequestMethod(ZgrabLoader loader) {
        this.loader = loader;
    }


    List<IScanIssue> doScan(byte[] baseReq, IHttpService service) {
        // todo handle non-zero bodies
        //int bodySize = baseReq.length - Utilities.getBodyStart(baseReq);
        //Utilities.out(""+bodySize);

        baseReq = Utilities.addOrReplaceHeader(baseReq, "Transfer-Encoding", "chunked");
        baseReq = Utilities.addOrReplaceHeader(baseReq, "Content-Length", "5");
        baseReq = Utilities.setBody(baseReq, "0\r\n\r\n");
        Response syncedResp = request(service, baseReq);
        if (syncedResp.timedOut()) {
            Utilities.out("Timeout on first request. Aborting.");
            return null;
        }

        byte[] reverseLength = Utilities.setHeader(baseReq, "Content-Length", "4");
        Response truncatedChunk = request(service, reverseLength);
        if (truncatedChunk.timedOut()) {
            Utilities.out("Reporting reverse timeout technique worked");
            report("Request smuggling v1-b", "Status:timeout", syncedResp, truncatedChunk);
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
        if (!badLengthResp.timedOut() && badLengthResp.getReq().getStatusCode() == syncedResp.getReq().getStatusCode()) {
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
            short badChunkCode = badChunkResp.getReq().getStatusCode();
            if (! (badChunkResp.timedOut() || (badChunkCode != badLengthResp.getReq().getStatusCode() && badChunkCode != syncedResp.getReq().getStatusCode()))) {
                Utilities.out("Bad chunk didn't affect status code and chunk timeout failed. Aborting.");
                return null;
            }
        }

        report("Request smuggling v1", "Status:BadChunkDetection:BadLengthDetected", syncedResp, badChunkResp, badLengthResp);
        return null;
    }

    private void report(String title, String detail, Response... requests) {
        IHttpRequestResponse base = requests[0].getReq();
        IHttpService service = base.getHttpService();

        IHttpRequestResponse[] reqs = new IHttpRequestResponse[requests.length];
        for (int i=0; i<requests.length; i++) {
            reqs[i] = requests[i].getReq();
        }
        Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(base.getRequest(), service), reqs, title, "Status:timeout", "High", "Tentative", "Abandon Akamai"));
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    Response request(IHttpService service, byte[] req) {
        IHttpRequestResponse resp;

        if (loader == null) {
            resp = Utilities.callbacks.makeHttpRequest(service, req);
        }
        else {
            byte[] response = loader.getResponse(service.getHost(), req);
            if (response == null) {
                try {
                    String template = Utilities.helpers.bytesToString(req).replace(service.getHost(), "%d");
                    String name = Integer.toHexString(template.hashCode());
                    PrintWriter out = new PrintWriter("/Users/james/PycharmProjects/zscanpipeline/generated-requests/"+name);
                    out.print(template);
                    out.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }

                Utilities.out("Couldn't find response. Sending via Burp instead");
                Utilities.out(Utilities.helpers.bytesToString(req));
                return new Response(Utilities.callbacks.makeHttpRequest(service, req));
                //throw new RuntimeException("Couldn't find response");
            }

            if (Arrays.equals(response, "".getBytes())) {
                response = null;
            }

            resp = new Request(req, response, service);
        }

        return new Response(resp);
    }


}

class Response {
    private IHttpRequestResponse req;
    private IResponseInfo info;
    private IResponseVariations attributes;
    private boolean timedOut;

    Response(IHttpRequestResponse req) {
        this.req = req;
        this.timedOut = req.getResponse() == null;
        if (!timedOut) {
            this.info = Utilities.helpers.analyzeResponse(req.getResponse());
            this.attributes = Utilities.helpers.analyzeResponseVariations(req.getResponse());
        }
    }

    IHttpRequestResponse getReq() {
        return req;
    }

    IResponseInfo getInfo() {
        return info;
    }

    IResponseVariations getAttributes() {
        return attributes;
    }

    boolean timedOut() {
        return timedOut;
    }
}

class Request implements IHttpRequestResponse {

    private byte[] req;
    private byte[] resp;
    private IHttpService service;

    Request(byte[] req, byte[] resp, IHttpService service) {
        this.req = req;
        this.resp = resp;
        this.service = service;
    }

    @Override
    public byte[] getRequest() {
        return req;
    }

    @Override
    public void setRequest(byte[] message) {
        this.req = message;
    }

    @Override
    public byte[] getResponse() {
        return resp;
    }

    @Override
    public void setResponse(byte[] message) {
        this.resp = message;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.service = httpService;
    }

    @Override
    public String getHost() {
        return service.getHost();
    }

    @Override
    public int getPort() {
        return service.getPort();
    }

    @Override
    public String getProtocol() {
        return service.getProtocol();
    }

    @Override
    public void setHost(String s) {

    }

    @Override
    public void setPort(int i) {

    }

    @Override
    public void setProtocol(String s) {

    }

    @Override
    public URL getUrl() {
        return Utilities.getURL(req, service);
    }

    @Override
    public short getStatusCode() {
        return 0;
    }
}


class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public String getHost() {
        return null;
    }

    public int getPort() {
        return 0;
    }

    public String getProtocol() {
        return null;
    }
}