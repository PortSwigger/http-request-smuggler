package burp;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

class SmuggleHelper {

    private RequestEngine engine;
    private List<Resp> reqs = new LinkedList<>();
    private IHttpService service;
    private int id = 0;

    SmuggleHelper(IHttpService service) {
        this.service = service;
        String url = service.getProtocol()+"://"+service.getHost()+":"+service.getPort();
        if (Utilities.globalSettings.getBoolean("use turbo for autopoc")) {
            this.engine = new ThreadedRequestEngine(url, 1, 20, 1, 1, 0, this::callback, 10, null, 1024, false);
        }
        else {
            this.engine = new BurpRequestEngine(url, 1, 20, 0, this::callback, null, true);
        }
    }

    void queue(String req) {
        engine.queue(req, new ArrayList<>(), 0, null, null, null, 0, 0); // , Integer.toString(id++)
    }

    private boolean callback(Request req, boolean interesting) {
        reqs.add(new Resp(new Req(req.getRequestAsBytes(), req.getResponseAsBytes(), service), System.currentTimeMillis()));
        return false;
    }

    List<Resp> waitFor() {
        //engine.start(10);
        engine.showStats(60);
        return reqs;
    }

    // todo move into turbo intruder?
}