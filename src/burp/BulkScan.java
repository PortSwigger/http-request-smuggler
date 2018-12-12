package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.concurrent.*;

import static java.lang.Math.min;
import static org.apache.commons.lang3.math.NumberUtils.max;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

class BulkScanLauncher {

    private static ScanPool taskEngine;

    BulkScanLauncher(Scan scan) {
        taskEngine = buildTaskEngine();
        Utilities.callbacks.registerContextMenuFactory(new OfferBulkScan(scan));
    }

    private static ScanPool buildTaskEngine() {
        BlockingQueue<Runnable> tasks;
        tasks = new LinkedBlockingQueue<>();


        ScanPool taskEngine = new ScanPool(Utilities.globalSettings.getInt("thread pool size"), Utilities.globalSettings.getInt("thread pool size"), 10, TimeUnit.MINUTES, tasks);
        Utilities.globalSettings.registerListener("thread pool size", value -> {
            Utilities.out("Updating active thread pool size to "+value);
            try {
                taskEngine.setCorePoolSize(Integer.parseInt(value));
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
            } catch (IllegalArgumentException e) {
                taskEngine.setMaximumPoolSize(Integer.parseInt(value));
                taskEngine.setCorePoolSize(Integer.parseInt(value));
            }
        });
        return taskEngine;
    }

    static ScanPool getTaskEngine() {
        return taskEngine;
    }
}

class BulkScan implements Runnable  {
    private IHttpRequestResponse[] reqs;
    private Scan scan;
    private ConfigurableSettings config;

    BulkScan(Scan scan, IHttpRequestResponse[] reqs, ConfigurableSettings config) {
        this.scan = scan;
        this.reqs = reqs;
        this.config = config;
    }

    public void run() {
        ScanPool taskEngine = BulkScanLauncher.getTaskEngine();

        int queueSize = taskEngine.getQueue().size();
        Utilities.log("Adding "+reqs.length+" tasks to queue of "+queueSize);
        queueSize += reqs.length;
        int thread_count = taskEngine.getCorePoolSize();

        ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));
        Collections.shuffle(reqlist);

        int cache_size = thread_count;
        if (config.getBoolean("max one per host")) {
            cache_size = queueSize;
        }

        Set<String> keyCache = new HashSet<>();
        boolean useKeyCache = config.getBoolean("max one per host+status");

        Queue<String> cache = new CircularFifoQueue<>(cache_size);
        HashSet<String> remainingHosts = new HashSet<>();

        int i = 0;
        int queued = 0;
        // every pass adds at least one item from every host
        while(!reqlist.isEmpty()) {
            Utilities.log("Loop "+i++);
            Iterator<IHttpRequestResponse> left = reqlist.iterator();
            while (left.hasNext()) {
                IHttpRequestResponse req = left.next();

                String host = req.getHttpService().getHost();
                String key = req.getHttpService().getProtocol()+host;
                if (req.getResponse() != null) {
                    IResponseInfo info = Utilities.helpers.analyzeResponse(req.getResponse());
                    key = key + info.getStatusCode() + info.getInferredMimeType();
                }

                if (useKeyCache && keyCache.contains(key)) {
                    left.remove();
                    continue;
                }

                if (!cache.contains(host)) {
                    cache.add(host);
                    keyCache.add(key);
                    left.remove();
                    Utilities.log("Adding request on "+host+" to queue");
                    queued++;

                    taskEngine.execute(new BulkScanItem(scan, req));
                } else {
                    remainingHosts.add(host);
                }
            }

            if(config.getBoolean("max one per host")) {
                break;
            }

            if (remainingHosts.size() <= 1 && !useKeyCache) {
                left = reqlist.iterator();
                while (left.hasNext()) {
                    queued++;
                    taskEngine.execute(new BulkScanItem(scan, left.next()));
                }
                break;
            }
            else {
                cache = new CircularFifoQueue<>(max(min(remainingHosts.size()-1, thread_count), 1));
            }
        }

        Utilities.out("Queued " + queued + " attacks");

    }
}

class RandomComparator implements Comparator<Object> {
    @Override
    public int compare(Object o1, Object o2) {
        int h1 = o1.hashCode();
        int h2 = o2.hashCode();
        if (h1 < h2) {
            return -1;
        }
        else  if (h1 == h2) {
            return 0;
        }
        return 1;
    }
}

class TriggerBulkScan implements ActionListener {

    private IHttpRequestResponse[] reqs;
    private Scan scan;

    TriggerBulkScan(Scan scan, IHttpRequestResponse[] reqs) {
        this.scan = scan;
        this.reqs = reqs;
    }

    public void actionPerformed(ActionEvent e) {
        ConfigurableSettings config = Utilities.globalSettings.showSettings();
        if (config != null) {
            BulkScan bulkScan = new BulkScan(scan, reqs, config);
            (new Thread(bulkScan)).start();
        }
    }
}

class OfferBulkScan implements IContextMenuFactory {
    private Scan scan;

    OfferBulkScan(Scan scan) {
        this.scan = scan;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        if(reqs.length == 0) {
            return options;
        }

        JMenuItem probeButton = new JMenuItem("Launch bulk scan");
        probeButton.addActionListener(new TriggerBulkScan(scan, reqs));
        options.add(probeButton);

        return options;
    }
}

class BulkScanItem implements Runnable {

    private final IHttpRequestResponsePersisted baseReq;
    private final Scan scanner;

    BulkScanItem(Scan scanner, IHttpRequestResponse baseReq) {
        this.baseReq = Utilities.callbacks.saveBuffersToTempFiles(baseReq);
        this.scanner = scanner;
    }

    public void run() {
        scanner.doScan(baseReq.getRequest(), this.baseReq.getHttpService());
    }
}

interface Scan extends IScannerCheck {
    List<IScanIssue> doScan(byte[] baseReq, IHttpService service);

    default List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }
}

class ScanPool extends ThreadPoolExecutor implements IExtensionStateListener {

    ScanPool(int corePoolSize, int maximumPoolSize, long keepAliveTime, TimeUnit unit, BlockingQueue<Runnable> workQueue) {
        super(corePoolSize, maximumPoolSize, keepAliveTime, unit, workQueue);
        Utilities.callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void extensionUnloaded() {
        getQueue().clear();
        shutdown();
    }
}