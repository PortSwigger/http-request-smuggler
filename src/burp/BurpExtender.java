package burp;

import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    static final String name = "HTTP Request Smuggler";
    private static final String version = "2.03";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = BulkScan.hostsToSkip;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        HashMap<String, Object> settings = new HashMap<>();
        
        new Utilities(callbacks, settings, name);
        callbacks.setExtensionName(name);
        Utilities.callbacks.registerExtensionStateListener(this);

        new DesyncBox();

        new PauseDesyncScan("Sketchy pause");
        new ImplicitZeroScan("Implicit zero");
        new ClientDesyncScan("Client desync");
        new OldClientDesyncScan("Old client desync");
        //new ClientDesyncScan("Client-desync probe");
        new ChunkContentScan("Smuggle probe");
        new H1TunnelScan("H/1 Tunnel probe");
        new SecondRequestScan("Second-request scan");

        new HTTP2Scan("HTTP/2 probe");
        new HeadScanTE("HTTP/2 Tunnel probe TE");
        new H2TunnelScan("HTTP/2 Tunnel probe CL");
        new HiddenHTTP2("HTTP/2-hidden probe");
        new HTTP2Scheme("HTTP/2 :scheme probe");
        new HTTP2DualPath("HTTP/2 dual :path probe");
        new HTTP2Method("HTTP/2 :method probe");
        new HTTP2FakePseudo("HTTP/2 fake-pseudo probe");

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