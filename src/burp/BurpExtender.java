package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    static final String name = "HTTP Request Smuggler";
    private static final String version = "1.13";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        HashMap<String, Object> settings = new HashMap<>();
        settings.put("skip straight to poc", false);
        settings.put("poc: G", false);
        settings.put("poc: headerConcat", false);
        settings.put("poc: bodyConcat", false);
        settings.put("poc: collab", false);
        settings.put("poc: collab-header", false);
        settings.put("poc: collab-XFO-header", false);
        settings.put("poc: collab-abs", false);
        settings.put("poc: collab-at", false);
        settings.put("poc: collab-blind", false);
        settings.put("poc-collab domain", "manual-collab-domain-here");
        settings.put("use turbo for autopoc", true);
        settings.put("skip vulnerable hosts", false);
        settings.put("skip obsolete permutations", false);
        settings.put("only report exploitable", false);
        settings.put("risky mode", false);
        settings.put("pad everything", false);
        
        new Utilities(callbacks, settings, name);
        callbacks.setExtensionName(name);
        Utilities.callbacks.registerExtensionStateListener(this);

        new DesyncBox();

        new ChunkContentScan("Smuggle probe");
        new HTTP2Scan("HTTP/2 probe");
        new HeadScanTE("HTTP/2 Tunnel probe TE");
        new HeadScanCL("HTTP/2 Tunnel probe CL");
        new HiddenHTTP2("HTTP/2-hidden probe");

        // todo these need testing
        new HTTP2Scheme("HTTP/2 :scheme probe");
        new HTTP2DualPath("HTTP/2 dual :path probe");
        new HTTP2Method("HTTP/2 :method probe");

        //new PipelineDesync("Pipeline probe");
        new SmuggleMenu();
        new BulkScanLauncher(BulkScan.scans);


        callbacks.registerContextMenuFactory(new SuggestAttack());
        Utils.setBurpPresent(callbacks);

        Utilities.out("Loaded " + name + " v" + version);
    }

    public void extensionUnloaded() {
        Utilities.log("Aborting all attacks");
        Utilities.unloaded.set(true);
    }

}