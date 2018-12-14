package burp;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "Smuggle Scan";
    private static final String version = "0.1";
    public boolean unloaded = false;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
        Utilities.callbacks.registerExtensionStateListener(this);

        SmuggleScan scanner = new SmuggleScan();
        new BulkScanLauncher(scanner);

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

