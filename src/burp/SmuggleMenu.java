package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class SmuggleMenu implements IContextMenuFactory {

    SmuggleMenu() {
        Utilities.callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] reqs = invocation.getSelectedMessages();
        List<JMenuItem> options = new ArrayList<>();

        if(reqs == null || reqs.length != 1) {
            return options;
        }

        byte[] req = reqs[0].getRequest();

        if ( Utilities.getBodyStart(req) < req.length || Utilities.containsBytes(req, "Content-Length".getBytes())) {
            JMenuItem probeButton = new JMenuItem("Convert to chunked");
            probeButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    // need a handle on an IMessageEditorTab
                    reqs[0].setRequest(SmuggleScanBox.makeChunked(reqs[0].getRequest(), 0, 0));
                }
            });

            options.add(probeButton);

            JMenuItem gzipButton = new JMenuItem("GZIP encode body");
            gzipButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    // need a handle on an IMessageEditorTab
                    reqs[0].setRequest(SmuggleScanBox.gzipBody(reqs[0].getRequest()));
                }
            });
            options.add(gzipButton);
        }

        return options;
    }
}
