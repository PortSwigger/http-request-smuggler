package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

class EarlyBodyPair extends PermutationPair {
    String terminatorTemplate;

    EarlyBodyPair(String name, HttpHeader terminator, PermutationOutcome expectedOutcome) {
        super(name, expectedOutcome);
        terminatorTemplate = terminator.name() + ": " + terminator.value() + "\r\n{significant}";
    }

    EarlyBodyPair(String name, String terminator, PermutationOutcome expectedOutcome) {
        super(name, expectedOutcome);
        this.terminatorTemplate = terminator;
    }


    private HttpRequest addHeader(HttpRequest request, String template, SignificantHeader significantHeader, boolean dummySuffix) {
        String suffix;
        if (dummySuffix) {
            suffix = "A: B\r\nfoo: bar";
        } else {
            suffix = "A: B\r\n" + significantHeader;
        }
        suffix = suffix + "\r\n\r\n" + significantHeader.getBody();
        //suffix = suffix + "\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nFoo: B";
        //suffix = suffix + "\r\n\r\n0\r\n\r\n";//GET / HTTP/1.1\r\nFoo: B";
        //suffix = suffix + "\r\n\r\nGET /robots.txt HTTP/1.1\r\nFoo: bar";//GET / HTTP/1.1\r\nFoo: B";
        int bodySize = suffix.length() + 10;

        if (significantHeader.shouldRemoveCL()) {
            request = request.withRemovedHeader("Content-Length");
        } else if (!significantHeader.name().toLowerCase().endsWith("ontent-length") && request.hasHeader("Content-Length")) {
            request = request.withRemovedHeader("Content-Length").withAddedHeader("Content-Length", "" + bodySize);
            suffix = suffix + "A".repeat(bodySize);
        }

        return HttpRequest.httpRequest(request.httpService(), request.toString().replaceFirst("\r\n\r\n", "\r\n" + template.replace("{significant}", suffix)));
    }

    @Override
    List<MontoyaRequestResponse> checkForContamination(SignificantHeader header, HttpRequest original) {
        return ContaminationTest.victimCheck(original, transformIntoHidden(original, header, false), false);
    }

    @Override
    HttpRequest transformIntoBaseline(HttpRequest request, SignificantHeader significantHeader, boolean makeMissing) {
        request = removeIfRequired(request, significantHeader);
        return addHeader(request.withAddedHeader(convertToDummy(significantHeader, makeMissing)), terminatorTemplate, significantHeader, true);
    }

    @Override
    HttpRequest transformIntoHidden(HttpRequest request, SignificantHeader significantHeader, boolean makeMissing) {
        request = removeIfRequired(request, significantHeader);
        return addHeader(request, terminatorTemplate, convertToDummy(significantHeader, makeMissing), false);
    }

    @Override
    void probe(HttpRequest base, String details) {
        // plan:
        // confirm TE is used
        // and confirm CL is used
        // -> vulnerability maybe!
        // only works for POST

        details = "\n" + details;
        ArrayList<HttpRequest> bases = new ArrayList<HttpRequest>();
        bases.add(base.withMethod("GET"));
        bases.add(base.withMethod("POST"));

        // scenarios:
        // H.X nuke:
        // H.X split: detected
        // X.H nuke
        // X.H split


        for (HttpRequest baseReq : bases) {
            // this doesn't work since the hidden CL won't get forwarded to cause a timeout
            // MontoyaRequestResponse bodyNotForwarded = Scan.request(permutor.transformIntoHidden(baseReq, new SignificantHeader("bodyNotForwarded", "Content-Length", "10", "A".repeat(10), false), false), true);

            MontoyaRequestResponse bodyNotForwarded = Scan.request(transformIntoBaseline(baseReq, new SignificantHeader("bodyNotForwarded", "Content-Length", "50", "B".repeat(50), false, false), false), true);
            if (bodyNotForwarded.status() == 0) {
                // H.CL
                // front-end didn't see the header, so it didn't forward the body
                // back-end saw the header but didn't receive the body, so it timed out
                // confirm: no body
                MontoyaRequestResponse noBody = Scan.request(transformIntoBaseline(baseReq, new SignificantHeader("noBody", "Content-Length", "0", "", false, false), false), true);
                String desc;
                // todo is there something wrong with my detection? why isn't it finding anything?
                if (noBody.status() != 0) {
                    desc = "H.CL confirmed";
                } else {
                    desc = "H.CL bad";
                }
                bodyNotForwarded.annotations().setNotes(desc + details);
                noBody.annotations().setNotes(desc);
                BulkUtilities.montoyaApi.organizer().sendToOrganizer(bodyNotForwarded);
                BulkUtilities.montoyaApi.organizer().sendToOrganizer(noBody);
                // exploit with CL.TE

            }

            // test for TE.H
            MontoyaRequestResponse teHidden = Scan.request(transformIntoHidden(baseReq, new SignificantHeader("teHidden", "Transfer-Encoding", "chunked", "0\r\n\r\n" + "C".repeat(50), false, false), false), true);
            if (teHidden.status() == 0) {
                teHidden.annotations().setNotes("TE.H maybe" + details);
                BulkUtilities.montoyaApi.organizer().sendToOrganizer(teHidden);
                // exploit with TE.CL or CL.0
            }

            MontoyaRequestResponse teVisibleValid = Scan.request(transformIntoBaseline(baseReq, new SignificantHeader("teVisibleValid", "Transfer-Encoding", "chunked", "0\r\n\r\n", true, false), false), true);
            if (teVisibleValid.status() != 0) {
                // W gets FPs from WAFs, F would trigger a timeout but then you lose the server-header... should use both
                MontoyaRequestResponse teVisibleInvalid = Scan.request(transformIntoBaseline(baseReq, new SignificantHeader("teVisibleInvalid", "Transfer-Encoding", "chunked", "F\r\n\r\n", true, false), false), true);

                MontoyaRequestResponse invisibleInvalid = Scan.request(transformIntoHidden(baseReq, new SignificantHeader("invisibleInvalid", "Transfer-Encoding", "chunked", "F\r\n\r\n", true, false), false), true);
                MontoyaRequestResponse invisibleValid = Scan.request(transformIntoHidden(baseReq, new SignificantHeader("invisibleValid", "Transfer-Encoding", "chunked", "0\r\n\r\n", true, false), false), true);

                if (invisibleValid.serverStatus() == teVisibleValid.serverStatus() && invisibleInvalid.serverStatus() == teVisibleInvalid.serverStatus()) {
                    continue;
                }

                if (teVisibleValid.serverStatus() != teVisibleInvalid.serverStatus()) {

                    if (teVisibleValid.server() != teVisibleInvalid.server() && teVisibleValid.server() != 0) {
                        teVisibleValid.annotations().setNotes("TE.H highly likely" + details);
                        teVisibleInvalid.annotations().setNotes("TE.H highly likely" + details);
                        invisibleValid.annotations().setNotes("TE.H highly likely" + details);
                        invisibleInvalid.annotations().setNotes("TE.H highly likely" + details);
                    } else {
                        teVisibleValid.annotations().setNotes("TE.H possibly" + details);
                        teVisibleInvalid.annotations().setNotes("TE.H possibly" + details);
                        invisibleValid.annotations().setNotes("TE.H possibly" + details);
                        invisibleInvalid.annotations().setNotes("TE.H possibly" + details);
                    }

                    BulkUtilities.montoyaApi.organizer().sendToOrganizer(teVisibleValid);
                    BulkUtilities.montoyaApi.organizer().sendToOrganizer(teVisibleInvalid);
                    BulkUtilities.montoyaApi.organizer().sendToOrganizer(invisibleValid);
                    BulkUtilities.montoyaApi.organizer().sendToOrganizer(invisibleInvalid);
                }
            }
        }


//        MontoyaRequestResponse clMissing = Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("cl-valid", "Content-Length", "0", false), true), true);
//        MontoyaRequestResponse clValid = Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("cl-valid", "Content-Length", "0", false), false), true);
//        MontoyaRequestResponse clInvalid = Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("cl-invalid", "Content-Length", "Z", false), false), true);
//        if (clMissing.status() == 421) {
//            // at least one server responds with 421 if they don't see the CL header
//
//
//            // one server didn't see the CL header
//            if (clValid.serverStatus() == clInvalid.serverStatus()) {
//                // front-end didn't see the CL header, so the request was dropped without forwarding
//                // aka we have H.CL
//                // ideally, te requests should match too
//                // ideally, makeMissing non-hidden should give same status
//                // prove back-end supports TE
//                // exploit with CL.TE
//            } else {
//
//            }
//        }
//
//        // front-end saw the CL header - rejected one request and forwarded the other
//        // confirm with TE.CL:
//        //
//        // exploit with CL.0 or TE.CL
//
////        MontoyaRequestResponse clValid = Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("cl-valid", "Content-Length", "0", false), false), true);
////
////        MontoyaRequestResponse teValid = Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("te-valid", "Transfer-Encoding", "chunked", false), false), true);
////        MontoyaRequestResponse teInvalid = Scan.request(permutor.transformIntoHidden(base, new SignificantHeader("te-invalid", "Transfer-Encoding", "wrt", false), false), true);
//        if (421 == clInvalid.serverStatus() && 421 == clValid.serverStatus()) {
//            // front-end didn't see the CL header, so the request was dropped without forwarding
//            // ideally, status code should be 421
//            // ideally, te requests should match too
//            // ideally, makeMissing non-hidden should give same status
//            // prove back-end supports TE
//            // exploit with CL.TE
//        } else {
//
//        }
//
//
////        SignificantHeader left = new SignificantHeader("chunked-valid", "Transfer-Encoding", "chunked", "0\r\n\r\n", false);
////        SignificantHeader right = new SignificantHeader("chunked-invalid", "Transfer-Encoding", "chunked", "W\r\n\r\n", false);
//        // assert left != right
//        // repeat left & right but with CL: 0
    }

}
