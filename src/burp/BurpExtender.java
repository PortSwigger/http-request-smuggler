package burp;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "Smuggle Scan";
    private static final String version = "0.1";
    private ScanPool taskEngine;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);

        Utilities.callbacks.registerExtensionStateListener(this);
        Utilities.callbacks.registerScannerCheck(new SmuggleScan());

        new BulkScanLauncher(new SmuggleScan());

        ZgrabLoader x = new ZgrabLoader();
        //x.launchSmugglePipeline();


        Utilities.out("Loaded " + name + " v" + version);
    }

    public void extensionUnloaded() {
        Utilities.log("Aborting all attacks");
        Utilities.unloaded.set(true);
    }

}

