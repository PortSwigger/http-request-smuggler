package burp;

import org.apache.commons.collections4.queue.CircularFifoQueue;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.net.URL;
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


    private String getKey(IHttpRequestResponse req) {
        IRequestInfo reqInfo = Utilities.helpers.analyzeRequest(req.getRequest());

        StringBuilder key = new StringBuilder();
        key.append(req.getHttpService().getProtocol());
        key.append(req.getHttpService().getHost());

        if( config.getBoolean("key method")) {
            key.append(reqInfo.getMethod());
        }

        if (req.getResponse() != null) {
            IResponseInfo respInfo = Utilities.helpers.analyzeResponse(req.getResponse());

            if (config.getBoolean("key header names")) {
                StringBuilder headerNames = new StringBuilder();
                for (String header : respInfo.getHeaders()) {
                    headerNames.append(header.split(": ")[0]);
                }
                key.append(headerNames.toString());
            }

            if (config.getBoolean("key status")) {
                key.append(respInfo.getStatusCode());
            }

            if (config.getBoolean("key content-type")) {
                key.append(respInfo.getStatedMimeType());
            }

            if (config.getBoolean("key server")) {
                key.append(Utilities.getHeader(req.getRequest(), "Server"));
            }
        }

        return key.toString();
    }

    public void run() {
        ScanPool taskEngine = BulkScanLauncher.getTaskEngine();

        int queueSize = taskEngine.getQueue().size();
        Utilities.log("Adding "+reqs.length+" tasks to queue of "+queueSize);
        queueSize += reqs.length;
        int thread_count = taskEngine.getCorePoolSize();

        ArrayList<IHttpRequestResponse> reqlist = new ArrayList<>(Arrays.asList(reqs));
        Collections.shuffle(reqlist);

        int cache_size = queueSize; //thread_count;

        Set<String> keyCache = new HashSet<>();

        Queue<String> cache = new CircularFifoQueue<>(cache_size);
        HashSet<String> remainingHosts = new HashSet<>();

        String filterValue = Utilities.globalSettings.getString("filter");

        int i = 0;
        int queued = 0;

        // every pass adds at least one item from every host
        while(!reqlist.isEmpty()) {
            Utilities.log("Loop "+i++);
            Iterator<IHttpRequestResponse> left = reqlist.iterator();
            while (left.hasNext()) {
                IHttpRequestResponse req = left.next();

                if (!"".equals(filterValue)) {
                    if (!Utilities.containsBytes(req.getRequest(), filterValue.getBytes())) {
                        continue;
                    }
                }

                String host = req.getHttpService().getHost();
                if (cache.contains(host)) {
                    remainingHosts.add(host);
                    continue;
                }

                if (config.getBoolean("use key")) {
                    String key = getKey(req);
                    if (keyCache.contains(key)) {
                        left.remove();
                        continue;
                    }
                    keyCache.add(key);
                }

                cache.add(host);
                left.remove();
                Utilities.log("Adding request on "+host+" to queue");
                queued++;
                taskEngine.execute(new BulkScanItem(scan, req));
            }

            cache = new CircularFifoQueue<>(max(min(remainingHosts.size()-1, thread_count), 1));
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
    private IScanIssue[] issues;
    private Scan scan;

    TriggerBulkScan(Scan scan, IHttpRequestResponse[] reqs) {
        this.scan = scan;
        this.reqs = reqs;
    }

    TriggerBulkScan(Scan scan, IScanIssue[] issues) {
        this.scan = scan;
        this.issues = issues;
    }

    public void actionPerformed(ActionEvent e) {
        if (this.reqs == null) {
            this.reqs = new IHttpRequestResponse[issues.length];
            for (int i=0; i<issues.length; i++) {
                IScanIssue issue = issues[i];
                reqs[i] = new Req(Utilities.helpers.buildHttpRequest(issue.getUrl()), null, issue.getHttpService());
            }
        }

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

        JMenuItem probeButton = new JMenuItem("Launch "+scan.name);
        if(reqs != null && reqs.length > 0) {
            probeButton.addActionListener(new TriggerBulkScan(scan, reqs));
            options.add(probeButton);
        } else if(invocation.getSelectedIssues().length > 0) {
            probeButton.addActionListener(new TriggerBulkScan(scan, invocation.getSelectedIssues()));
            options.add(probeButton);
        }

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
        ScanPool engine = BulkScanLauncher.getTaskEngine();
        long done = engine.getCompletedTaskCount()+1;
        Utilities.out("Completed "+ done + " of "+(engine.getQueue().size()+done));
    }
}

abstract class Scan implements IScannerCheck {
    ZgrabLoader loader = null;
    String name = "";

    Scan(String name) {
        this.name = name;
        // Utilities.callbacks.registerScannerCheck(this);
    }

    abstract List<IScanIssue> doScan(byte[] baseReq, IHttpService service);

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return doScan(baseRequestResponse.getRequest(), baseRequestResponse.getHttpService());
    }

    void setRequestMethod(ZgrabLoader loader) {
        this.loader = loader;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    void report(String title, String detail, Resp... requests) {
        IHttpRequestResponse base = requests[0].getReq();
        IHttpService service = base.getHttpService();

        IHttpRequestResponse[] reqs = new IHttpRequestResponse[requests.length];
        for (int i=0; i<requests.length; i++) {
            reqs[i] = requests[i].getReq();
        }
        if (Utilities.isBurpPro()) {
            Utilities.callbacks.addScanIssue(new CustomScanIssue(service, Utilities.getURL(base.getRequest(), service), reqs, title, detail, "High", "Tentative", "."));
        } else {
            detail = detail.replace("right click on the attached request", "paste the first request into the repeater (including trailing whitespace), fill in the 'target' box, then right click on the request");

            StringBuilder serialisedIssue = new StringBuilder();
            serialisedIssue.append("Found issue: ");
            serialisedIssue.append(title);
            serialisedIssue.append("\n");
            serialisedIssue.append("Target: ");
            serialisedIssue.append(service.getProtocol());
            serialisedIssue.append("://");
            serialisedIssue.append(service.getHost());
            serialisedIssue.append("\n");
            serialisedIssue.append(detail);
            serialisedIssue.append("\n");
            serialisedIssue.append("Evidence: \n======================================\n");
            for (IHttpRequestResponse req: reqs) {
                serialisedIssue.append(Utilities.helpers.bytesToString(req.getRequest()));
                serialisedIssue.append("\n--------------------------------------\n");
                if (req.getResponse() == null) {
                    serialisedIssue.append("[no response]");
                }
                else {
                    serialisedIssue.append(Utilities.helpers.bytesToString(req.getResponse()));
                }
                serialisedIssue.append("\n======================================\n");
            }

            Utilities.out(serialisedIssue.toString());
        }
    }

    Resp request(IHttpService service, byte[] req) {
        return request(service, req, 0);
    }

    Resp request(IHttpService service, byte[] req, int maxRetries) {
        if (Utilities.unloaded.get()) {
            throw new RuntimeException("Aborting due to extension unload");
        }

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {

        }

        IHttpRequestResponse resp = null;
        long startTime = System.currentTimeMillis();
        if (loader == null) {
            int attempts = 0;
            while (( resp == null || resp.getResponse() == null) && attempts <= maxRetries) {
                startTime = System.currentTimeMillis();
                try {
                    byte[] responseBytes = Utilities.callbacks.makeHttpRequest(service, req).getResponse();
                    resp = new Req(req, responseBytes, service);
                } catch (java.lang.RuntimeException e) {
                    Utilities.out("Recovering from request exception: "+service.getHost());
                    Utilities.err("Recovering from request exception: "+service.getHost());
                    resp = new Req(req, null, service);
                }
                attempts += 1;
            }
        }
        else {
            byte[] response = loader.getResponse(service.getHost(), req);
            if (response == null) {
                try {
                    String template = Utilities.helpers.bytesToString(req).replace(service.getHost(), "%d");
                    String name = Integer.toHexString(template.hashCode());
                    PrintWriter out = new PrintWriter("/Users/james/PycharmProjects/zscanpipeline/generated-requests/"+name);
                    out.print(template);
                    out.close();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }

                Utilities.out("Couldn't find response. Sending via Burp instead");
                Utilities.out(Utilities.helpers.bytesToString(req));
                return new Resp(Utilities.callbacks.makeHttpRequest(service, req), startTime);
                //throw new RuntimeException("Couldn't find response");
            }

            if (Arrays.equals(response, "".getBytes())) {
                response = null;
            }

            resp = new Req(req, response, service);
        }

        return new Resp(resp, startTime);
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

class Resp {
    private IHttpRequestResponse req;
    private IResponseInfo info;
    private IResponseVariations attributes;

    public short getStatus() {
        return status;
    }

    private short status = 0;
    private boolean timedOut = false;
    private boolean failed = false;

    Resp(IHttpRequestResponse req, long startTime) {
        this.req = req;

        // fixme will interact badly with distribute-damage
        int burpTimeout = Integer.parseInt(Utilities.getSetting("project_options.connections.timeouts.normal_timeout"));
        int scanTimeout = Utilities.globalSettings.getInt("timeout") * 1000;

        if (burpTimeout == scanTimeout) {
            if (req.getResponse() == null) {
                this.timedOut = true;
                this.failed = true;
            }
        } else {
            if ((System.currentTimeMillis() - startTime) > scanTimeout) {
                if (req.getResponse() != null) {
                    Utilities.out("TImeout with response. Start time: " + startTime + " Current time: " + System.currentTimeMillis() + " Difference: " + (System.currentTimeMillis() - startTime) + " Tolerance: " + scanTimeout);
                }
                this.timedOut = true;
                this.failed = true;
            } else if (req.getResponse() == null) {
                this.failed = true;
            }
        }
        if (!this.failed) {
            this.info = Utilities.helpers.analyzeResponse(req.getResponse());
            this.attributes = Utilities.helpers.analyzeResponseVariations(req.getResponse());
            this.status = this.info.getStatusCode();
        }
    }

    IHttpRequestResponse getReq() {
        return req;
    }

    IResponseInfo getInfo() {
        return info;
    }

    IResponseVariations getAttributes() {
        return attributes;
    }

    boolean failed() {
        return failed;
    }

    boolean timedOut() {
        return timedOut;
    }
}

class Req implements IHttpRequestResponse {

    private byte[] req;
    private byte[] resp;
    private IHttpService service;

    Req(byte[] req, byte[] resp, IHttpService service) {
        this.req = req;
        this.resp = resp;
        this.service = service;
    }


    @Override
    public byte[] getRequest() {
        return req;
    }

    @Override
    public void setRequest(byte[] message) {
        this.req = message;
    }

    @Override
    public byte[] getResponse() {
        return resp;
    }

    @Override
    public void setResponse(byte[] message) {
        this.resp = message;
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String comment) {

    }

    @Override
    public String getHighlight() {
        return null;
    }

    @Override
    public void setHighlight(String color) {

    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.service = httpService;
    }

//    @Override
//    public String getHost() {
//        return service.getHost();
//    }
//
//    @Override
//    public int getPort() {
//        return service.getPort();
//    }
//
//    @Override
//    public String getProtocol() {
//        return service.getProtocol();
//    }
//
//    @Override
//    public void setHost(String s) {
//
//    }
//
//    @Override
//    public void setPort(int i) {
//
//    }
//
//    @Override
//    public void setProtocol(String s) {
//
//    }
//
//    @Override
//    public URL getUrl() {
//        return Utilities.getURL(req, service);
//    }
//
//    @Override
//    public short getStatusCode() {
//        return 0;
//    }
}


class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity,
            String confidence,
            String remediation) {
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.confidence = confidence;
        this.remediation = remediation;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public String getHost() {
        return null;
    }

    public int getPort() {
        return 0;
    }

    public String getProtocol() {
        return null;
    }
}