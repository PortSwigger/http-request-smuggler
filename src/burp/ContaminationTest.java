package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ContaminationTest extends Scan {

    ContaminationTest(String name) {
        super(name);
    }

    @Override
    List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse) {
        HttpRequest original = Utilities.buildMontoyaReq(Utilities.convertToHttp1(baseRequestResponse.getRequest()), baseRequestResponse.getHttpService());
        //original = original.withAddedHeader("Expect", "100-continue");
        original = original.withMethod("HEAD");

        HttpRequest harmless = original.withBody("");
        HttpRequest attack = original.withBody("G");
        List<MontoyaRequestResponse> result = victimCheck(harmless, attack, true);
        if (result != null) {
            return null;
        }

        victimCheck(harmless, attack.withBody("G"), true);
        return null;
    }

    static public List<MontoyaRequestResponse> victimCheck(HttpRequest base, HttpRequest attack, boolean report) {

        cleanConnection(base);
        if (checkStability(base, 5) != null) {
            return null;
        }

        List<MontoyaRequestResponse> results = null;
        MontoyaRequestResponse attackResponse = null;
        for (int i = 0; i < 10 && results == null; i++) {
            attackResponse = Scan.request(attack, true);
            results = checkStability(base, 3);
        }

        if (results == null) {
            return null;
        }

        cleanConnection(base);
        if (checkStability(base, 20) != null) {
                return null;
        }

        if (report) {
            String notes = "Contamination detected. Expected: " + results.get(0).status() + " Got: " + results.get(1).status();
            Scan.reportToOrganiser(notes, attackResponse, results.get(0), results.get(1));
        }

        return List.of(attackResponse, results.get(0), results.get(1));
    }

    private static void cleanConnection(HttpRequest base) {
        final int CLEAN_CONNECTION_COUNT = 5;

        for (int i = 0; i < CLEAN_CONNECTION_COUNT; i++) {
            Scan.request(base, true);
        }
    }

    private static List<MontoyaRequestResponse> checkStability(HttpRequest base, int confirmationCount) {

        MontoyaRequestResponse expectedResponse = Scan.request(base, true);

        for (int i = 0; i < confirmationCount; i++) {
            MontoyaRequestResponse response = Scan.request(base, true);
            if (response.status() != expectedResponse.status()) {
                if (PermutationResult.isWAF(response)) {
                    return null;
                }
                return List.of(expectedResponse, response);
            }
        }
        return null;
    }

}
