package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SmuggleScan implements  IScannerCheck {

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        try {
            byte[] req = baseRequestResponse.getRequest();
            req = Utilities.addOrReplaceHeader(req, "Transfer-Encoding", "chunked");
            req = Utilities.addOrReplaceHeader(req, "Content-Length", "5");

            ByteArrayOutputStream synced = new ByteArrayOutputStream();
            synced.write(Arrays.copyOfRange(req, 0, Utilities.getBodyStart(req)));
            synced.write("0\r\n\r\n".getBytes());
            Response syncedResp = request(baseRequestResponse.getHttpService(), synced.toByteArray());
            if (syncedResp.timedOut()) {
                Utilities.out("Timeout on first request. Aborting.");
                return null;
            }

            ByteArrayOutputStream badLength = new ByteArrayOutputStream();
            byte[] badLengthArray = Utilities.addOrReplaceHeader(req, "Content-Length", "6");
            badLength.write(Arrays.copyOfRange(badLengthArray, 0, Utilities.getBodyStart(badLengthArray)));
            badLength.write("0\r\n\r\n".getBytes());
            Response badLengthResp = request(baseRequestResponse.getHttpService(), badLength.toByteArray());
            if (!badLengthResp.timedOut() && badLengthResp.getReq().getStatusCode() == syncedResp.getReq().getStatusCode()) {
                Utilities.out("Overlong content length didn't cause a timeout or code-change. Aborting.");
                return null;
            }

            ByteArrayOutputStream badChunk = new ByteArrayOutputStream();
            badChunk.write(Arrays.copyOfRange(req, 0, Utilities.getBodyStart(req)));
            badChunk.write("Z\r\n\r\n".getBytes());
            Response badChunkResp = request(baseRequestResponse.getHttpService(), badChunk.toByteArray());
            if (badChunkResp.timedOut()) {
                Utilities.out("Bad chunk attack timed out. Aborting.");
                return null;
            }

            if (badChunkResp.getInfo().getStatusCode() == syncedResp.getInfo().getStatusCode()) {
                Utilities.out("Invalid chunk probe caused a timeout. Attempting chunk timeout instead.");
                ByteArrayOutputStream timeoutChunk = new ByteArrayOutputStream();
                timeoutChunk.write(Arrays.copyOfRange(req, 0, Utilities.getBodyStart(req)));
                timeoutChunk.write("1\r\n\r\n".getBytes());
                badChunkResp = request(baseRequestResponse.getHttpService(), timeoutChunk.toByteArray());
                short badChunkCode = badChunkResp.getReq().getStatusCode();
                if (! (badChunkResp.timedOut() || (badChunkCode != badLengthResp.getReq().getStatusCode() && badChunkCode != syncedResp.getReq().getStatusCode()))) {
                    Utilities.out("Bad chunk didn't affect status code and chunk timeout failed. Aborting.");
                    return null;
                }
            }

            IHttpRequestResponse[] reqs = new IHttpRequestResponse[3];
            reqs[0] = syncedResp.getReq();
            reqs[1] = badChunkResp.getReq();
            reqs[2] = badLengthResp.getReq();

            //ArrayList<IScanIssue> issues = new ArrayList<>();
            //issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), Utilities.getURL(baseRequestResponse), reqs, "Request Smuggling", "asdf", "High", "Tentative", "asdf"));
            Utilities.callbacks.addScanIssue(new CustomScanIssue(baseRequestResponse.getHttpService(), Utilities.getURL(baseRequestResponse), reqs, "Request Smuggling", "Status1:Status2:Timeout", "High", "Tentative", "Abandon Akamai"));

            return null;

        } catch (IOException e) {
            return null;
        }

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }



    private Response request(IHttpService service, byte[] req) {
        IHttpRequestResponse resp;
        resp = Utilities.callbacks.makeHttpRequest(service, req);
        if (resp.getResponse() == null) {
            Utilities.log("Request failed, retrying...");
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