package burp;

import java.util.ArrayList;
import java.util.Comparator;

public class PermutationResultGroup {
    ArrayList<PermutationResult> results;

    public PermutationResultGroup() {
        this.results = new ArrayList<PermutationResult>();
    }

    public void add(PermutationResult result) {
        this.results.add(result);
    }

    public void report() {
        if (results.isEmpty()) {
            return;
        }

        StringBuilder textDescription = new StringBuilder();
        results.sort(Comparator.comparingInt(PermutationResult::getScore).reversed());

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

            bestResult.report(textDescription.toString());

            if (!bestResult.isUnstable()) {
                bestResult.probe(textDescription.toString());
            }
        }
    }


}
