package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.List;

public class HeaderSmugglingScan extends Scan {

    boolean insideScanner = false;

    public HeaderSmugglingScan(String name) {
        super(name);
        scanSettings.register("rescan", false);
        scanSettings.register("research mode", true);
    }

    static HttpRequest stripToBase(HttpRequest req) {
        ArrayList<String> allowedHeaders = new ArrayList<>();
        allowedHeaders.add("User-Agent");
        allowedHeaders.add("Referer");
        allowedHeaders.add("Accept");
        allowedHeaders.add("Connection");
        allowedHeaders.add("Accept-Encoding");
        allowedHeaders.add("Accept-Language");
        HttpRequest out = HttpRequest.httpRequest().withMethod(req.method()).withService(req.httpService()).withPath(req.path());
        out = out.withAddedHeader("Host", req.httpService().host());
        for (HttpHeader header: req.headers()) {
            if (allowedHeaders.contains(header.name())) {
                out = out.withAddedHeader(header.name(), header.value());
            }
        }
        return out;
    }


    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse) {
        doScan(Utilities.buildMontoyaReq(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService()));
        return null;
    }

    Report doScan(HttpRequest original) {
        original = Utilities.convertToHttp1(original);
        if (Utilities.globalSettings.getBoolean("rescan")) {
            original = stripToBase(original);
        }
        original = original.withUpdatedHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36");

        HttpRequest base = original.withMethod("POST").withHeader("Content-Type", "application/x-www-form-urlencoded").withHeader("Content-Length", "0").withBody("");;

        boolean researchMode = Utilities.globalSettings.getBoolean("research mode");
        if (insideScanner) {
            researchMode = false;
        }

        // todo don't send a body with GET
        //base = base.withMethod("OPTIONS");

        ArrayList<SignificantHeader> canaryHeaders = new ArrayList<>();

        // detect back-end sees
        // front-end wouldn't forward this if it saw it
        canaryHeaders.add(new SignificantHeader("Host-invalid", "Host", "foo/bar", true));

        // detect front-end sees
        canaryHeaders.add(new SignificantHeader("Host-valid-missing", "Host", original.httpService().host(), false));
//        canaryHeaders.add(new SignificantHeader("Host-valid-dupe", "Host", baseRequestResponse.getHttpService().getHost(), true));
        //canaryHeaders.add(new SignificantHeader("Range-start", "Range", "bytes=0-10", false));

        // i3mtth51viviip18h1k3n8h2itokcd02.psres.net
        //canaryHeaders.add(new SignificantHeader("Host-collab", "Host", "i3mtth51viviip18h1k3n8h2itokcd02.psres.net", true));
        canaryHeaders.add(new SignificantHeader("CL-invalid", "Content-Length", "Z", true)); // GET

        // this is effective, but causes timeouts & desync on vulnerable targets
        if (researchMode) {
            canaryHeaders.add(new SignificantHeader("CL-valid", "Content-Length", "5", true));
        }
        //canaryHeaders.add(new SignificantHeader("Max-Forwards", "Max-Forwards", "X", true));
        //canaryHeaders.add(new SignificantHeader("TE", "Transfer-Encoding", "chunked", false));
//        canaryHeaders.add(new SignificantHeader("Transfer-Encoding", "chunked"));
//        canaryHeaders.add(new SignificantHeader("Long", "X".repeat(8300)));

        // detect front-end sees
        // front-end should forward this - we're relying on missing headers causing a back-end error

        //canaryHeaders.add(new SignificantHeader("Expect", "Expect", "100-continue", false));


        ArrayList<PermutationPair> permutors = new ArrayList<>();

 //       permutors.add(new EarlyBodyPair("nsplit1", "X-Foo: foo\n\n{significant}", PermutationOutcome.HIDDEN));
//        permutors.add(new EarlyBodyPair("nsplit4", "X-Foo: foo\r\n\n{significant}", PermutationOutcome.HIDDEN));
//        permutors.add(new EarlyBodyPair("nsplit2", "X-Foo: foo\n \n{significant}", PermutationOutcome.NOTDESYNC));
//        permutors.add(new EarlyBodyPair("nsplit3", "X-Foo: foo\n\r\n{significant}", PermutationOutcome.NOTDESYNC));
//        permutors.add(new EarlyBodyPair("spacesplit", "X-Foo: bar\r\n \r\n{significant}", PermutationOutcome.NOTDESYNC));
////        permutors.add(new EarlyBodyPair("paddr",  HttpHeader.httpHeader("Pad", "X".repeat(8000)), PermutationOutcome.VISIBLE));
//        // permutors.add(new EarlyBodyPair("spammr",  HttpHeader.httpHeader("Spam", "Spam:foo\r\nFoo: bar".repeat(200)), PermutationOutcome.VISIBLE));
////        permutors.add(new EarlyBodyPair("cookie", "Cookie: foo=\"\r\n\r\n\"\r\n{significant}", PermutationOutcome.HIDDEN));
//
////        permutors.add(new EarlyBodyPair("namesplit", "Nil\r\n\r\n{significant}", PermutationOutcome.HIDDEN));
//        permutors.add(new EarlyBodyPair("null-term", HttpHeader.httpHeader("X-Null", "foo\0\r\n{significant}"), PermutationOutcome.NOTDESYNC));
////        permutors.add(new EarlyBodyPair("null-split", HttpHeader.httpHeader("X-Null", "foo\r\0\n\r\n{significant}"), PermutationOutcome.NOTDESYNC));
//        permutors.add(new EarlyBodyPair("invalidsplit", "Bad name:\r\n\r\n{significant}", PermutationOutcome.HIDDEN));
////        permutors.add(new EarlyBodyPair("nonamebreak", ":\r\n{significant}", PermutationOutcome.NOTDESYNC));
////        permutors.add(new EarlyBodyPair("nonamesplit", ":\r\n\r\n{significant}", PermutationOutcome.HIDDEN));
//
//        // todo request with no headers... or just a space
//        permutors.add(new EarlyBodyPair("nsplit-name", HttpHeader.httpHeader("X-Foo", "foo\n\nbar: x"), PermutationOutcome.HIDDEN));
//        permutors.add(new EarlyBodyPair("rsplit", HttpHeader.httpHeader("Arrr", "foo\r\rbar"), PermutationOutcome.VISIBLE));
        //       permutors.add(new EarlyBodyPair("r2split", HttpHeader.httpHeader("Arrr", "foo\r\r\nbar"), PermutationOutcome.VISIBLE));


        permutors.add(new HiddenPair("space", HideTechnique.SPACE, PermutationOutcome.NOTDESYNC));
        permutors.add(new HiddenPair("tab", HideTechnique.TAB, PermutationOutcome.NOTDESYNC));
        permutors.add(new HiddenPair("wrap", HideTechnique.WRAP, PermutationOutcome.NOTDESYNC));
        permutors.add(new HiddenPair("hop", HideTechnique.HOP, PermutationOutcome.NOTDESYNC));
        permutors.add(new HiddenPair("lpad", HideTechnique.LPAD, PermutationOutcome.NOTDESYNC));

//        permutors.add(new HiddenPair("underflip", HideTechnique.SPACE, PermutationOutcome.NOTDESYNC));
        //permutors.add(new HiddenPair("skiphop", HideTechnique.SKIPHOP, PermutationOutcome.NOTDESYNC));






        // permutors.add(new EarlyBodyPair("no-value", HttpHeader.httpHeader("Nil\r\nFoo", "bar"), PermutationOutcome.VISIBLE));

        boolean testedServerStability = false;
        PermutationResultGroup results = new PermutationResultGroup();
        int baseStatus = 0;
        for (PermutationPair permutor: permutors ) {
            for (SignificantHeader canaryHeader : canaryHeaders) {
                try {
                    PermutationResult result = new PermutationResult(base, canaryHeader, permutor);
                    if (result.isInteresting()) {
                        if (!researchMode) {
                            if (result.consistent(3) != null) {
                                // todo blacklist server
                                return null;
                            } else {
                                result.setConfirmed(true);
                            }
                        } else {
                            // clean the connection pool
                            for (int i = 0; i < 5; i++) {
                                request(base, true);
                            }

                            int stabilityConfirmationRequirement = 10;
                            MontoyaRequestResponse surpriseResponse = result.consistent(5);
                            if (surpriseResponse != null) {
                                result.recordInstability(surpriseResponse);
                                stabilityConfirmationRequirement = 30;
                            } else {
                                result.setConfirmed(true);
                            }


                            if (!testedServerStability) {
                                // clean the connection pool
                                for (int i = 0; i < 5; i++) {
                                    request(base, true);
                                }

                                result.baseStatus = request(base, true).serverStatus();
                                for (int i = 0; i < stabilityConfirmationRequirement; i++) {
                                    if (request(base, true).serverStatus() != result.baseStatus) {
                                        return null;
                                    }
                                }
                                testedServerStability = true;
                            }

                            result.recordContamination(permutor.checkForContamination(canaryHeader, base));

                            if (result.isConfirmed()) {
                                result.setType(splitOrNuke(permutor, base));
                            }
                        }
                    }

                    results.add(result);
                } catch (Exception e) {
                    if (e.toString().contains("java.net.UnknownHostException")) {
                        return null;
                    }
                    e.printStackTrace();
                }
            }
        }

        Report report = results.buildReport(researchMode);
        if (!insideScanner && report != null) {
            if (Utilities.globalSettings.getBoolean("report to organizer")) {
                report.sendToOrganizer();
            } else {
                AuditIssue issue = report.getIssue();
                Utilities.montoyaApi.siteMap().add(issue);
            }
        }
        return report;
    }

    private static SplitOrNuke splitOrNuke(PermutationPair permutor, HttpRequest base) {
        SignificantHeader properOverlong = new SignificantHeader("CL-overlong", "Content-Length", "1000", false);
        HttpRequest test = permutor.transformIntoBaseline(base, properOverlong, false);
        if (request(test, true).status() != 0) {
            if (base.method().equals("POST")) {
                base = base.withMethod("POST");
                test = permutor.transformIntoBaseline(base, properOverlong, false);
            }
            if (request(test, true).status() != 0) {
                return SplitOrNuke.CL_IGNORED;
            }
        }

        // fixme this isn't right - CL 10 could cause a timeout due to incomplete headers being forwarded
        // fixme could rely on built-in CL updating instead?
        SignificantHeader legitCL = new SignificantHeader("Nada", "Irrelevant", "foo", false);
        // SignificantHeader legitCL = new SignificantHeader("Content-Length", "10", false);
        test = permutor.transformIntoBaseline(base, legitCL, false);
        if (request(test, true).status() == 0) {
            return SplitOrNuke.TIMEOUT;
        }

        SignificantHeader maybeOverlong = new SignificantHeader("CL-10", "Content-Length", "10", false);
        test = permutor.transformIntoBaseline(base, maybeOverlong, false).withBody("A");
        if (request(test, true).status() == 0) {
            return SplitOrNuke.SPLIT;
        } else {
            return SplitOrNuke.NUKE;
        }
    }


}

enum SplitOrNuke {
    UNKNOWN,
    CL_IGNORED,
    TIMEOUT,
    SPLIT,
    NUKE
}



