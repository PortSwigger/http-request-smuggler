package burp;

import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "Smuggle Scan";
    private static final String version = "0.2";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
        Utilities.callbacks.registerExtensionStateListener(this);

        ChunkContentScan scanner = new ChunkContentScan("CL/TE");
        new SmuggleMenu();
        new BulkScanLauncher(scanner);

        new BulkScanLauncher(new DualContentScan("CL-CL"));

        Utils.setBurpPresent(callbacks);
        //ZgrabLoader x = new ZgrabLoader(scanner);
        //x.launchSmugglePipeline();


        Utilities.out("Loaded " + name + " v" + version);
    }

    public void extensionUnloaded() {
        Utilities.log("Aborting all attacks");
        Utilities.unloaded.set(true);
    }

}

