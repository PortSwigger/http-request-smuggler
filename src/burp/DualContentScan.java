package burp;

import java.util.List;

public class DualContentScan extends Scan implements IScannerCheck  {

    DualContentScan(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan ( byte[] baseReq, IHttpService service){
        return null;
    }
}