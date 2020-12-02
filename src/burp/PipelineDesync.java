package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import static burp.HeadScanTE.mixedResponse;

public class PipelineDesync extends SmuggleScanBox implements IScannerCheck {

        PipelineDesync(String name) {
            super(name);
        }

        public boolean doConfiguredScan(byte[] original, IHttpService service, HashMap<String, Boolean> config) {
            if (!config.containsKey("vanilla")) {
                return false;
            }

            //original = setupRequest(original);
            original = Utilities.addOrReplaceHeader(original, "Accept-Encoding", "identity");
            original = Utilities.addOrReplaceHeader(original, "User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36");
            original = Utilities.addCacheBuster(original, Utilities.generateCanary());
            //byte[] base = Utilities.addOrReplaceHeader(original, "Transfer-Encoding", "chunked");
            byte[] base = Utilities.addOrReplaceHeader(original, "Connection", "keep-alive");
            base = Utilities.setMethod(base, "HEAD");

            try {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                outputStream.write(base);
                outputStream.write(original);
                byte[] attack = Utilities.fixContentLength(Utilities.addOrReplaceHeader(outputStream.toByteArray(), "Content-Length", "1"));
                Resp resp = request(service, attack);

                if (mixedResponse(resp)) {
                    report("Pipeline desync (HTTP2)", "", resp);
                    return true;
                } else if (mixedResponse(resp, false)) {
                    recordCandidateFound();
                    SmuggleHelper helper = new SmuggleHelper(service);
                    helper.queue(Utilities.helpers.bytesToString(attack));
                    List<Resp> results = helper.waitFor();
                    if (mixedResponse(results.get(0), false)) {
                        report("Pipeline desync (HTTP1)", "", resp, results.get(0));
                        return true;
                    }
                }


            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            return false;
        }
}
