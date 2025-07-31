package burp;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

enum PermutationOutcome {
    IGNORED, HIDDEN, BLOCKED, BLOCKED2, WEIRD, VISIBLE, DISCREPANCY, NODESYNC
}

public abstract class PermutationPair {
    String name = null;
    PermutationOutcome expectedOutcome;

    PermutationPair(String name, PermutationOutcome expectedOutcome) {
        this.name = name;
        this.expectedOutcome = expectedOutcome;
    }

    String getName() {
        return name;
    }

    abstract List<MontoyaRequestResponse> checkForContamination(SignificantHeader header, HttpRequest base);

    abstract HttpRequest transformIntoBaseline(HttpRequest request, SignificantHeader significantHeader, boolean dummy);

    abstract HttpRequest transformIntoHidden(HttpRequest request, SignificantHeader significantHeader, boolean dummy);

    abstract void probe(HttpRequest base, String details);

    SignificantHeader convertToDummy(SignificantHeader header, boolean hideHeader) {
        if (!hideHeader) {
            return header;
        }
        // better hope header name doesn't start with z
        return new SignificantHeader(header.getLabel(), "z"+header.name().substring(1), header.value(), header.keepOriginal());
    }

    boolean isExpectedOutcome(PermutationOutcome outcome) {
        if (expectedOutcome == PermutationOutcome.NODESYNC) {
            return outcome != PermutationOutcome.DISCREPANCY;
        }
        return outcome == expectedOutcome;
    }

    HttpRequest removeIfRequired(HttpRequest request, SignificantHeader significantHeader) {
        if (!significantHeader.keepOriginal()) {
            return request.withRemovedHeader(significantHeader);
        }
        return request;
    }
}

