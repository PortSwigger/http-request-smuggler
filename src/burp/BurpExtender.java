package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    static final String name = "HTTP Request Smuggler";
    private static final String version = "2.01";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = BulkScan.hostsToSkip;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        HashMap<String, Object> settings = new HashMap<>();
        
        new Utilities(callbacks, settings, name);
        callbacks.setExtensionName(name);
        Utilities.callbacks.registerExtensionStateListener(this);

        new DesyncBox();

        new BrowserH2DesyncScan("Browser H/2 desync");
        new ClientDesyncKeepaliveScan("Browser desync");
        //new ClientDesyncScan("Client-desync probe");
        new ChunkContentScan("Smuggle probe");
        new H1TunnelScan("H/1 Tunnel probe TE");
        new SecondRequestScan("Second-request scan");

        new HTTP2Scan("HTTP/2 probe");
        new HeadScanTE("HTTP/2 Tunnel probe TE");
        new HeadScanCL("HTTP/2 Tunnel probe CL");
        new HiddenHTTP2("HTTP/2-hidden probe");
        new HTTP2Scheme("HTTP/2 :scheme probe");
        new HTTP2DualPath("HTTP/2 dual :path probe");
        new HTTP2Method("HTTP/2 :method probe");

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