package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Arrays;

public class Report {

    String title;
    String detail;
    String remediation = "";
    String background = "";
    ArrayList<HttpRequestResponse> requests;
    AuditIssueSeverity severity;

    public Report(String notes, HttpRequestResponse... requests) {
        this.detail = notes;
        this.requests = new ArrayList<>();
        add(requests);
    }

    public Report(String title, String detail, String background, String remediation, AuditIssueSeverity severity, HttpRequestResponse... requests) {
        this.title = title;
        this.remediation = remediation;
        this.detail = detail;
        this.severity = severity;
        this.requests = new ArrayList<>();
        this.background = background;
        add(requests);
    }

    public void add(HttpRequestResponse... requests) {
        this.requests.addAll(Arrays.asList(requests));
    }

    public void sendToOrganizer() {
        Scan.reportToOrganiser(detail, requests.toArray(new HttpRequestResponse[0]));
    }

    public AuditIssue getIssue() {
        return AuditIssue.auditIssue(title, detail.replaceAll("\n", "<br/>\n"), remediation, requests.getFirst().request().url(), severity, AuditIssueConfidence.TENTATIVE, background.replaceAll("\n", "<br/>\n"), "", severity, requests);
    }

}
