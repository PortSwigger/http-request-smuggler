package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class PermutationResultGroup {
    ArrayList<PermutationResult> results;

    public PermutationResultGroup() {
        this.results = new ArrayList<PermutationResult>();
    }

    public void add(PermutationResult result) {
        this.results.add(result);
    }

    public Report buildReport(boolean researchMode) {
        if (results.isEmpty()) {
            return null;
        }

        StringBuilder textDescription = new StringBuilder();
        results.sort(Comparator.comparingInt(PermutationResult::getScore).reversed());
        Report report = null;
        boolean split = false;
        PermutationResult bestResult = results.get(0);
        if (bestResult.isInteresting() && (bestResult.isConfirmed() || bestResult.isSuprising() || bestResult.contaminationResults != null )) {
            for (PermutationResult result: results) {
                if (!split && (!result.isConfirmed() && !result.isSuprising())) {
                    textDescription.append("\n");
                    split = true;
                }
                textDescription.append(result.getDescription());
                textDescription.append("\n");
            }

            List<HttpRequestResponse> reqs = bestResult.getRequests();
            // todo nix non-desync reports
            String detail = "The target appears to use a chain of webservers with discrepancies in how they parse HTTP/1 requests. This can lead to HTTP Request Smuggling vulnerabilities, or enable attackers to spoof front-end headers. To confirm the level of risk, run HTTP Request Smuggler in Burp Suite, and follow up with manual testing. ";
            String background = "https://portswigger.net/web-security/request-smuggling\n" +
                               "https://portswigger.net/research/http1-must-die";
            String remediation = "If possible, configure all reverse proxies to use HTTP/2 for upstream connections.";

            String fullDetail;
            if (researchMode) {
                fullDetail = textDescription + "\n\n" + detail;
            } else {
                fullDetail = detail + "\n\n" + textDescription;
            }

            report = new Report("HTTP Parser Discrepancy", fullDetail, background, remediation, AuditIssueSeverity.MEDIUM, reqs.toArray(new HttpRequestResponse[0]));

            if (researchMode && !bestResult.isUnstable()) {
                bestResult.probe(textDescription.toString());
            }
        }

        return report;
    }


}
