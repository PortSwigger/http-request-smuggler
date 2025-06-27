package burp;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PermutationResult {
    MontoyaRequestResponse canaryPresent;
    MontoyaRequestResponse canaryMissing;
    MontoyaRequestResponse hiddenCanaryPresent;
    MontoyaRequestResponse hiddenCanaryMissing;
    PermutationOutcome outcome;
    PermutationPair permutor;
    SignificantHeader canaryHeader;
    HttpRequest base;
    SplitOrNuke type = SplitOrNuke.UNKNOWN;

    int baseStatus = 0;
    boolean unstable = false;
    boolean surprise = false;
    List<MontoyaRequestResponse> contaminationResults = null;

    MontoyaRequestResponse surpriseResponse = null;
    boolean confirmed = false;

    public void setType(SplitOrNuke type) {
        this.type = type;
    }

    public boolean isUnstable() {
        return unstable;
    }

    public boolean isSuprising() {
        return surprise;
    }

    public void setConfirmed(boolean confirmed) {
        this.confirmed = confirmed;
    }

    public void recordContamination(List<MontoyaRequestResponse> responses) {
        if (responses == null) {
            return;
        }
        this.contaminationResults = responses;
    }

    public void recordInstability(MontoyaRequestResponse surpriseResponse) {
        int surpriseCode = surpriseResponse.status();
        if (surpriseCode != 429 && surpriseCode != 0 && canaryPresent.status() != 0 && canaryMissing.status() != 0 && hiddenCanaryPresent.status() != 0 && hiddenCanaryMissing.status() != 0) {
            this.surpriseResponse = surpriseResponse;
            this.surprise = true;
        } else {
            this.unstable = true;
        }
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public void probe(String desc) {
        permutor.probe(base, desc);
    }


    private void probeForCL0() {
        // prove a server sees the CL even when it's hidden, by triggering a timeout
        // then prove a server doesn't see the CL when it's hidden, via a 421
        // fancy version: don't rely on 421 code
    }

    private void probeForTEH() {

    }

    private void probeForCLTE() {

    }


    public void exploit() {
//        List<SignificantHeader> attacks = new ArrayList<SignificantHeader>();
//
//        // valid exploit for U.S split & U.S nuke
//        String payload = "GET /robots.txt HTTP/1.1\r\nFoo: bar\r\nX-AA: ";
//        attacks.add(new SignificantHeader("attack-CL.TE", "Transfer-Encoding", "chunked", "0\r\n\r\n"+payload, false));
//
//        // exploit for S.U split
//        // todo need to predict exact CL size before
//        // todo need to sort out body with CL too
//        // String chunkSize = Integer.toHexString(payload.length());
//        // attacks.add(new SignificantHeader("attack-TE.CL", "Transfer-Encoding", "chunked", chunkSize+"\r\n"+payload+"0\r\n\r\n", false));
//
//        // exploit for S.U nuke (GET only)
//        attacks.add(new SignificantHeader("attack-CL.0", "Content-Length", ""+payload.length(), payload, false));
//
//        // todo S.U split
//        // can I make headers that are valid HTTP request line? maybe with line wrapping?
//
//        // todo what if TE isn't supported?
//
//        for (SignificantHeader attackHeader: attacks) {
//            MontoyaRequestResponse lastResp = null;
//            for (int i = 0; i < 15; i++) {
//                MontoyaRequestResponse resp = Scan.request(permutor.transformIntoHidden(base, attackHeader, false), true);
//                if (resp.status() == 0) {
//                    break;
//                }
//
//                if (lastResp != null) {
//                    if (resp.status() != lastResp.status()) {
//                        String desc = "Gotcha? "+resp.status() + "/" + lastResp.status();
//                        resp.annotations().setNotes(desc);
//                        lastResp.annotations().setNotes(desc);
//                        BulkUtilities.montoyaApi.organizer().sendToOrganizer(resp);
//                        BulkUtilities.montoyaApi.organizer().sendToOrganizer(lastResp);
//                        return;
//                    }
//                }
//                lastResp = resp;
//            }
//        }
//
//        Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("attack-host1", "Host", "av9ll9xtnanaaht09tcvf09ualgc46sv.psres.net", "", false), false), true);
//        Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("attack-host2", "Host", "8ktja7mrc8c8zfiyyr1t4yyszj5at5hu.psres.net", "", true), false), true);
    }


    public int getScore() {
        int score = 0;

        if (contaminationResults != null) {
            score += 70000;
        }

        if (surprise) {
            score += 30000;
        }

        if (confirmed) {
            score += 20000;
//            if (canaryMissing.serverStatus() == baseStatus) {
//                score += 10000;
//            }
        }

        score += (this.outcome.ordinal() * 2000);
        if (hiddenCanaryMissing.status() != 0) {
            score += (600 - hiddenCanaryMissing.status());
        }
        if (hiddenCanaryPresent.status() != 0) {
            score += (600 - hiddenCanaryPresent.status());
        }

        return score;
    }

    public PermutationResult(HttpRequest base, SignificantHeader canaryHeader, PermutationPair permutor) {
        this.permutor = permutor;
        this.base = base;
        this.canaryHeader = canaryHeader;
        canaryPresent =  Scan.request(permutor.transformIntoBaseline(base, canaryHeader, false), true);
        canaryMissing =  Scan.request(permutor.transformIntoBaseline(base, canaryHeader, true), true);
        hiddenCanaryPresent =  Scan.request(permutor.transformIntoHidden(base, canaryHeader, false), true);
        hiddenCanaryMissing =  Scan.request(permutor.transformIntoHidden(base, canaryHeader, true), true);
        outcome = classify();
    }

    MontoyaRequestResponse consistent(int iterations) {

        for (int i = 0; i < iterations; i++) {
            MontoyaRequestResponse surprise = Scan.request(permutor.transformIntoBaseline(base, canaryHeader, false), true);
            if (canaryPresent.status() != surprise.status()) {
                return surprise;
            }
        }

        for (int i = 0; i < iterations; i++) {
            MontoyaRequestResponse surprise = Scan.request(permutor.transformIntoBaseline(base, canaryHeader, true), true);
            if (canaryMissing.status() != surprise.status()) {
                return surprise;
            }
        }

        for (int i = 0; i < iterations; i++) {
            MontoyaRequestResponse surprise = Scan.request(permutor.transformIntoHidden(base, canaryHeader, false), true);
            if (hiddenCanaryPresent.status() != surprise.status()) {
                return surprise;
            }
        }

        for (int i = 0; i < iterations; i++) {
            MontoyaRequestResponse surprise = Scan.request(permutor.transformIntoHidden(base, canaryHeader, true), true);
            if (hiddenCanaryMissing.status() != surprise.status()) {
                return surprise;
            }
        }
        return null;
    }

    boolean isInteresting() {
        if (permutor.isExpectedOutcome(outcome) || outcome == PermutationOutcome.BLOCKED || outcome == PermutationOutcome.IGNORED || outcome == PermutationOutcome.BLOCKED2) {
            return false;
        }
        return true;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (obj.getClass() != this.getClass()) {
            return false;
        }

        final PermutationResult other = (PermutationResult) obj;
        if (other.outcome != outcome) {
            return false;
        }

        if (canaryPresent.serverStatus() != other.canaryPresent.serverStatus()) {
            return false;
        } else if (canaryMissing.serverStatus() != other.canaryMissing.serverStatus()) {
            return false;
        } else if (hiddenCanaryPresent.serverStatus() != other.hiddenCanaryPresent.serverStatus()) {
            return false;
        } else if (hiddenCanaryMissing.serverStatus() != other.hiddenCanaryMissing.serverStatus()) {
            return false;
        }

        return true;
    }

    String getDescription() {
        StringBuilder description = new StringBuilder();

        if (confirmed) {
            if (canaryMissing.serverStatus() == baseStatus) {
                description.append("CLEAN");
                description.append(" ");
            }
        }

        description.append(outcome.name());
        description.append(" ");
        description.append(permutor.getName());
        description.append(" ");
        description.append(canaryHeader.getLabel());
        description.append(" ");
        description.append(canaryPresent.status());
        description.append("/");
        description.append(canaryMissing.status());
        description.append("/");
        description.append(hiddenCanaryPresent.status());
        description.append("/");
        description.append(hiddenCanaryMissing.status());

        if (type != SplitOrNuke.UNKNOWN) {
            description.append(" ");
            description.append(type.name());
        }

        if (contaminationResults != null) {
            description.append(" CONTAMINATION: ");
            description.append(contaminationResults.get(1).status());
            description.append("/");
            description.append(contaminationResults.get(2).status());
        }

        if (surprise) {
            description.append(" SURPRISE-"+surpriseResponse.status());
        }

        if (unstable) {
            description.append(" UNSTABLE");
        }

        return description.toString();
    }

    void report(String notes) {
        Scan.reportToOrganiser(notes, canaryPresent, canaryMissing, hiddenCanaryPresent, hiddenCanaryMissing);

        if (surpriseResponse != null) {
            surpriseResponse.annotations().setNotes(notes);
            BulkUtilities.montoyaApi.organizer().sendToOrganizer(surpriseResponse);
        }

        if (contaminationResults != null) {
            for (MontoyaRequestResponse response: contaminationResults) {
                response.annotations().setNotes(notes);
                BulkUtilities.montoyaApi.organizer().sendToOrganizer(response);
            }
        }
    }

    private ArrayList<MontoyaRequestResponse> getResponses() {
        return new ArrayList<MontoyaRequestResponse>(Arrays.asList(canaryPresent, canaryMissing, hiddenCanaryPresent, hiddenCanaryMissing));
    }

    public static boolean isWAF(MontoyaRequestResponse response) {
        List<String> wafHeaderNames = Arrays.asList("cf-mitigated", "x-amzn-waf-action");
        List<String> wafBodyText = Arrays.asList("Request Rejected", "Just a moment...", "Attention Required!", "Incapsula incident ID", "Something went wrong.  That action is not allowed.", "This request was blocked by our web application firewall", "The page you are trying to access has blocked you", "Sorry, you have been blocked");

        if (response.hasResponse()) {
            for (String bodyText: wafBodyText) {
                if (response.response().contains(bodyText, false)) {
                    return true;
                }
            }
            for (String headerName: wafHeaderNames) {
                if (response.response().hasHeader(headerName)) {
                    return true;
                }
            }
        }
        return false;
    }

    private PermutationOutcome classify() {
        int hiddenCanaryPresentStatus = hiddenCanaryPresent.serverStatus();
        int hiddenCanaryMissingStatus = hiddenCanaryMissing.serverStatus();
        int canaryMissingStatus = canaryMissing.serverStatus();
        int canaryPresentStatus = canaryPresent.serverStatus();

        List<String> wafHeaderNames = Arrays.asList("cf-mitigated", "x-amzn-waf-action");
        List<String> wafBodyText = Arrays.asList("Request Rejected", "Just a moment...", "Attention Required!");

        for (MontoyaRequestResponse response: getResponses()) {
            if (isWAF(response)) {
                return PermutationOutcome.BLOCKED;
            }
        }

        // all responses identical - header not significant
        if (hiddenCanaryPresentStatus == hiddenCanaryMissingStatus && hiddenCanaryPresentStatus == canaryMissingStatus && hiddenCanaryPresentStatus == canaryPresentStatus) {
            return PermutationOutcome.IGNORED;
        }

        // header is significant, technique hid header, but no evidence of desync
        if (hiddenCanaryPresentStatus == hiddenCanaryMissingStatus && hiddenCanaryPresentStatus == canaryMissingStatus && hiddenCanaryPresentStatus != canaryPresentStatus) {
            return PermutationOutcome.HIDDEN;
        }

        // technique changed the response but the header is ignored
        if (hiddenCanaryPresentStatus == hiddenCanaryMissingStatus && hiddenCanaryPresentStatus != canaryPresentStatus) {
            return PermutationOutcome.BLOCKED;
        }

        // header is significant, but technique had no effect
        if (canaryPresentStatus == hiddenCanaryPresentStatus && canaryMissingStatus == hiddenCanaryMissingStatus && canaryPresentStatus != canaryMissingStatus) {
            return PermutationOutcome.VISIBLE;
        }

        // technique revealed a unique response
        if (hiddenCanaryPresentStatus != hiddenCanaryMissingStatus && hiddenCanaryMissingStatus == canaryMissingStatus && hiddenCanaryPresentStatus != canaryPresentStatus) {
            return PermutationOutcome.DESYNC;
        }

        // technique changed the response but the header is ignored
        if (hiddenCanaryPresentStatus == hiddenCanaryMissingStatus) {
            return PermutationOutcome.BLOCKED2;
        }

        // technique hid the header but also changed the response

        return PermutationOutcome.WEIRD;
    }
}
