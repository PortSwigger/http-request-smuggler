package burp;

import java.util.concurrent.ConcurrentHashMap;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    private static final String name = "HTTP Request Smuggler TEST";
    private static final String version = "1.07";
    public boolean unloaded = false;
    static ConcurrentHashMap<String, Boolean> hostsToSkip = new ConcurrentHashMap<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        new Utilities(callbacks);
        callbacks.setExtensionName(name);
        Utilities.callbacks.registerExtensionStateListener(this);

        ChunkContentScan scanner = new ChunkContentScan("Smuggle probe");
        new SmuggleMenu();
        new BulkScanLauncher(scanner);
        new DesyncBox();

        callbacks.registerContextMenuFactory(new SuggestAttack());
        Utils.setBurpPresent(callbacks);

        Utilities.out("Loaded " + name + "v" + version);
    }

    public void extensionUnloaded() {
        Utilities.log("Aborting all attacks");
        Utilities.unloaded.set(true);
    }

}

