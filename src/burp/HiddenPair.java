package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

enum HideTechnique {
    SPACE,
    WRAP,
    TAB,
    LPAD,
    HOP,
    SKIPHOP,
    DUPE,
    UNDER,
    NWRAP,
    RWRAP
}

class HiddenPair extends PermutationPair {
    HideTechnique hideType;

    HiddenPair(String name, HideTechnique hideType, PermutationOutcome expectedOutcome) {
        super(name, expectedOutcome);
        this.hideType = hideType;
    }

    @Override
    HttpRequest transformIntoBaseline(HttpRequest request, SignificantHeader significantHeader, boolean dummy) {
        request = removeIfRequired(request, significantHeader);
        return transform(request.withAddedHeader(convertToDummy(significantHeader, dummy)), new SignificantHeader("dummy", "dummy", significantHeader.value(), false));
    }

    @Override
    HttpRequest transformIntoHidden(HttpRequest request, SignificantHeader significantHeader, boolean dummy) {
        request = removeIfRequired(request, significantHeader);
        return transform(request, convertToDummy(significantHeader, dummy));
    }

    HttpRequest transform(HttpRequest request, SignificantHeader targetHeader) {
        // request = removeIfRequired(request, targetHeader);
        byte[] bytes;

        switch (hideType) {
            case SPACE:
                request = request.withAddedHeader(targetHeader.name() + " ", targetHeader.value());
                break;
            case WRAP:
                request = request.withAddedHeader(targetHeader.name(), "\r\n "+targetHeader.value());
                break;
            case TAB:
                request = request.withAddedHeader(targetHeader.name()+"\t", targetHeader.value());
                break;
            case LPAD:
                request = request.withAddedHeader("X-Junk", "x").withAddedHeader(" "+targetHeader.name(), targetHeader.value());
                break;
            case HOP:
                request = request.withAddedHeader(targetHeader.name(), targetHeader.value()).withAddedHeader("Connection", targetHeader.name());
                break;
            case SKIPHOP:
                request = request.withAddedHeader(targetHeader.name(), targetHeader.value()).withAddedHeader("Connection ", targetHeader.name());
                break;
            case DUPE:
                request = request.withAddedHeader(targetHeader).withAddedHeader(targetHeader);
                break;
            case UNDER:
                request = request.withAddedHeader(targetHeader.name().replace("-", "_"), targetHeader.value());
                break;
            case NWRAP:
                bytes = request.toByteArray().getBytes();
                bytes = Utilities.addOrReplaceHeader(bytes, "X-Junk: x\n"+targetHeader.name(), targetHeader.value());
                request = HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(bytes));
                break;
            case RWRAP:
                bytes = request.toByteArray().getBytes();
                bytes = Utilities.addOrReplaceHeader(bytes, "X-Junk: x\r"+targetHeader.name(), targetHeader.value());
                request = HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(bytes));
                break;
            default:
                throw new IllegalArgumentException("Invalid hide type");
        }

        return request;
    }

    @Override
    void probe(HttpRequest base, String details) {

        if (detect0CLwithExpect(base.withMethod("POST"))) {
            return;
        }


        if (detect0CLwithExpect(base.withMethod("GET"))) {
            return;
        }
//
        if (detect0CLWithTimeout(base.withMethod("POST"))) {
            return;
        }


        if (detect0CLWithTimeout(base.withMethod("GET"))) {
            return;
        }

        detectCL0(base.withMethod("POST"));



        //exploitCL0(base);
    }

    boolean detect0CLWithTimeout(HttpRequest base) {

        base = base.withBody("ABCDEFG").withHeader("Content-Length", "7");
        HttpRequest probe = transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", false), false);
        MontoyaRequestResponse hiddenCL = Scan.request(probe, true);
        if (!hiddenCL.timedOut()) {
            return false;
        }

        HttpRequest probe2 = transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", true), true);
        MontoyaRequestResponse visibleCL = Scan.request(probe2, true);
        if (visibleCL.timedOut() || hiddenCL.status() == visibleCL.status()) {
            return false;
        }

        // todo repeat with big timeout to get better evidence
        Scan.reportToOrganiser("0.CL timeout-detection v1: "+hiddenCL.status()+"/"+visibleCL.status(), visibleCL, hiddenCL);
        return true;
    }

    boolean detect0CLwithExpect(HttpRequest base) {
        // fixme false-negative when back-end doesn't wait for body. workaround: target HTML content-type

        //HttpRequest probe = transformIntoHidden(base.withMethod("POST").withBody("ABC=DEF").withHeader("Content-Length", "7"), new SignificantHeader("dummy", "Expect", "100-continue", false), false);
        base = base.withBody("ABCDEFG").withHeader("Expect", "100-continue").withHeader("Content-Length", "7").withHeader("Connection", "keep-alive");
        HttpRequest probe = transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", false), false);

        MontoyaRequestResponse hiddenCL = Scan.request(probe, true);
        if (hiddenCL.status() != 100) {
            return false;
        }
        short hiddenCLStatus = hiddenCL.nestedStatus();

        HttpRequest probe2 = transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", true), true);
        MontoyaRequestResponse visibleCL = Scan.request(probe2, true);

        if (visibleCL.status() == 0) {
            return false;
        }

        // this check can cause FNs
//        if (visibleCL.status() != 100) {
//            return;
//        }

        short visibleCLStatus = visibleCL.nestedStatus();
        if (visibleCL.status() == 100 && hiddenCLStatus == visibleCLStatus) {
            return false;
        }

        Scan.reportToOrganiser("0.CL expect-detection v2: "+hiddenCLStatus+"/"+visibleCLStatus, visibleCL, hiddenCL);
        return true;
    }

    List<MontoyaRequestResponse> checkForContamination(SignificantHeader header, HttpRequest original) {
        return ContaminationTest.victimCheck(original, transformIntoHidden(original.withBody("ABCDEFG"), header, false), false);
    }

    boolean detectCL0(HttpRequest base) {
        base = base.withBody("").withHeader("Content-Length", "7").withHeader("Connection", "keep-alive");
        MontoyaRequestResponse visibleCLMissingBody = Scan.request(transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", true), true), true);
        MontoyaRequestResponse hiddenCLMissingBody = Scan.request(transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", false), false), true);

        if (visibleCLMissingBody.serverStatus() == hiddenCLMissingBody.serverStatus()) {
            return false;
        }

        MontoyaRequestResponse noCL = Scan.request(transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", false), true), true);
        if (noCL.serverStatus() == hiddenCLMissingBody.serverStatus() || noCL.serverStatus() == visibleCLMissingBody.serverStatus()) {
            return false;
        }

        MontoyaRequestResponse regular = Scan.request(transformIntoHidden(base.withBody("ABCDEFG"), new SignificantHeader("CL", "Content-Length", "7", true), true), true);
        if (regular.serverStatus() == visibleCLMissingBody.serverStatus() || regular.serverStatus() == noCL.serverStatus()) {
            return false;
        }

        String type = "";
        if (regular.serverStatus() == hiddenCLMissingBody.serverStatus()) {
            type = "back-end nowait";
        } else {
            type = "back-end wait";
        }

        MontoyaRequestResponse hiddenCLWithBody = Scan.request(transformIntoHidden(base.withBody("ABCDEFG"), new SignificantHeader("CL", "Content-Length", "7", false), false), true);
        if (hiddenCLWithBody.status() == 0) {
            return false;
        }
        if (!(hiddenCLWithBody.response().hasHeader("Connection") && hiddenCLWithBody.response().headerValue("Connection").equalsIgnoreCase("close"))) {
            type += " alive? ";
        }

        String shortReport = "CL.0 detection v0.2-"+type+ " "+visibleCLMissingBody.status()+"/"+hiddenCLMissingBody.status()+"/"+noCL.status()+"/"+regular.status();
        Scan.reportToOrganiser(shortReport, visibleCLMissingBody, hiddenCLMissingBody, noCL, regular, hiddenCLWithBody);

        return true;
    }

    boolean detectCL0old(HttpRequest base) {
        /*
        Given front-end that forwards Expect header and waits:
            visible expect, hidden CL, no body: full response from back-end
            visible expect, visible CL, no body: triggers 100 from back-end
        Given front-end that response with 100:
            both trigger 100

            todo work this out
         */
        base = base.withBody("").withHeader("Expect", "100-continue").withHeader("Content-Length", "7");;
        HttpRequest hiddenProbe = transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", false), false);

        MontoyaRequestResponse hiddenCL = Scan.request(hiddenProbe, true);
        if (hiddenCL.status() == 100 && hiddenCL.nestedStatus() == 0) {
            return false;
        }

        HttpRequest visibleProbe = transformIntoHidden(base, new SignificantHeader("CL", "Content-Length", "7", false), true);
        MontoyaRequestResponse visibleCL = Scan.request(visibleProbe, true);
        if (visibleCL.status() != 100 || visibleCL.nestedStatus() != 0) {
            return false;
        }

        Scan.reportToOrganiser("CL.0 expect-detection v0.1: "+hiddenCL.status(), visibleCL, hiddenCL);

        return true;
    }

    void exploitCL0(HttpRequest base) {
        ArrayList<HttpRequest> bases = new ArrayList<HttpRequest>();
        bases.add(base.withMethod("GET"));
        bases.add(base.withMethod("POST"));
        for (HttpRequest probe: bases) {
            probe = probe.withBody("X");
            HttpRequest poison = transformIntoHidden(probe, new SignificantHeader("dummy", "Content-Length", "1", false), false);
            ContaminationTest.victimCheck(base, poison, true);
        }

    }

}
