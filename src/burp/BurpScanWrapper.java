package burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;

import java.util.HashSet;

// todo make generic & move to bulkScan
public class BurpScanWrapper implements ActiveScanCheck {
    private HashSet<String> keys = new HashSet<>();

    @Override
    public String checkName() {
        return BurpExtender.name;
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse httpRequestResponse, AuditInsertionPoint auditInsertionPoint, Http http) {

        // todo maybe just use server header
        String key = httpRequestResponse.httpService().toString() + new MontoyaRequestResponse(httpRequestResponse).server();
        if (keys.contains(key)) {
            return null;
        }
        keys.add(key);

        HeaderSmugglingScan scan = new HeaderSmugglingScan("asdf");
        scan.insideScanner = true;
        Report report = scan.doScan(httpRequestResponse.request());
        if (report == null) {
            return null;
        }
        return AuditResult.auditResult(report.getIssue());
    }
}
