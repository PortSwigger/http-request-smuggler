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

        if(reqs.length != 1) {
            return options;
        }

        JMenuItem probeButton = new JMenuItem("Convert to chunked");
        probeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // need a handle on an IMessageEditorTab
                reqs[0].setRequest(SmuggleScan.makeChunked(reqs[0].getRequest(), 0, 0));
            }
        });

        options.add(probeButton);

        return options;
    }
}
