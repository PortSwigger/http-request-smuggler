package burp;

import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "Desynchronize";
    private static final String version = "0.2";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
        callbacks.setExtensionName("Desynchronize");
        Utilities.callbacks.registerExtensionStateListener(this);

        ChunkContentScan scanner = new ChunkContentScan("Desync probe");
        new SmuggleMenu();
        new BulkScanLauncher(scanner);

        //new BulkScanLauncher(new DualContentScan("CL-CL"));

        callbacks.registerContextMenuFactory(new SuggestAttack());
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

