package burp;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class SuggestAttack implements IContextMenuFactory {

    final static String UNKNOWN = "";
    final static String CLTE = "CL.TE";
    final static String TECL = "TE.CL";
    final static String H2TE = "H2.TE";
    final static String H2TUNNEL = "H2-TUNNEL";

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> options = new ArrayList<>();

        // todo add support for click on the scanner issue itself?
        if (invocation != null && invocation.getSelectedMessages() != null && invocation.getSelectedMessages().length > 0 && invocation.getSelectedMessages()[0] != null) {

            IHttpRequestResponse message = invocation.getSelectedMessages()[0];
            String request = new String(message.getRequest());
            String headers = Utils.getHeaders(request).toLowerCase();




            if (headers.contains("chunked") || headers.contains("transfer-encoding")) {
                String type = "";
                if (invocation.getSelectedIssues() != null) {
                    String name = invocation.getSelectedIssues()[0].getIssueName();
                    if (name.contains("CL.TE")) {
                        type = CLTE;
                    }
                    else if (name.contains("TE.CL")) {
                        type = TECL;
                    } else  if (name.contains("H2.TE")) {
                        type = H2TE;
                    }
                }


                if (Utilities.isHTTP2(message.getRequest())) {
                    type = H2TE;
                    JMenuItem probeButton = new JMenuItem("Smuggle attack ("+type+")");
                    probeButton.addActionListener(new LaunchSuggestedAttack(message, type));
                    options.add(probeButton);
                } else if (type.equals(UNKNOWN)) {
                    type = CLTE;
                    JMenuItem probeButton = new JMenuItem("Smuggle attack ("+type+")");
                    probeButton.addActionListener(new LaunchSuggestedAttack(message, type));
                    options.add(probeButton);
                    type = TECL;
                    JMenuItem probeButton2 = new JMenuItem("Smuggle attack ("+type+")");
                    probeButton2.addActionListener(new LaunchSuggestedAttack(message, type));
                    options.add(probeButton2);
                } else {
                    JMenuItem probeButton = new JMenuItem("Smuggle attack ("+type+")");
                    probeButton.addActionListener(new LaunchSuggestedAttack(message, type));
                    options.add(probeButton);
                }
            } else if (Utilities.isHTTP2(message.getRequest()) && Utilities.containsBytes(message.getRequest(), "FOO BAR AAH".getBytes())) {
                String type = H2TUNNEL;
                JMenuItem probeButton = new JMenuItem("Smuggle attack ("+type+")");
                probeButton.addActionListener(new LaunchSuggestedAttack(message, type));
                options.add(probeButton);
            }

        }
        return options;
    }

}

class LaunchSuggestedAttack implements ActionListener {

    private IHttpRequestResponse message;
    private String type = SuggestAttack.UNKNOWN;

    LaunchSuggestedAttack(IHttpRequestResponse message, String type) {
        this.message = message;
        this.type = type;
    }

    @Override
    public void actionPerformed(ActionEvent e) {

        String PAYLOAD = "\r\n1\r\nZ\r\nQ\r\n\r\n";
        String H2PAYLOAD = "\r\na\r\n\r\n0\r\n\r\n";
        String request = new String(message.getRequest());
        String script;

        if (type.equals(SuggestAttack.H2TE)) {
            request = request.replaceFirst(H2PAYLOAD, "\r\n0\r\n\r\n");
            script = Utilities.getResource("/H2-TE.py");
        } else if (type.equals(SuggestAttack.H2TUNNEL)) {
            if (!request.contains("\r\n0\r\n\r\nFOO BAR")) {
                // stop Turbo from autofixing the content-length
                request = request.replaceFirst("Content-Length", "Content-length");
            }
            script = Utilities.getResource("/H2-TUNNEL.py");
        }
        else if (type.equals(SuggestAttack.CLTE)) {
            request = request.replaceFirst(PAYLOAD, "\r\n0\r\n\r\n");
            script = Utilities.getResource("/CL-TE.py");
        } else if (type.equals(SuggestAttack.TECL)) {
            script = Utilities.getResource("/TE-CL.py");
        } else {

            if (request.contains(PAYLOAD)) {
                // this is CL.TE
                script = Utilities.getResource("/CL-TE.py");
                request = request.replaceFirst(PAYLOAD, "\r\n0\r\n\r\n");
            } else {
                // this is either a normal chunked request, or TE.CL
                script = Utilities.getResource("/TE-CL.py");
            }
        }

        // amend the script to try and ensure the smuggled request gets a different response
        byte[] resp = message.getResponse();
        if (resp != null ) {
            String path = Utilities.helpers.analyzeRequest(message).getUrl().getPath();
            short responseCode = Utilities.helpers.analyzeResponse(resp).getStatusCode();
            if (responseCode == 404) {
                String newPath = "/";
                if (path.equals(newPath)) {
                    newPath = "/robots.txt";
                }

                script = script.replace("/hopefully404", newPath);
            }
        }

        new TurboIntruderFrame(message, new int[]{}, script, Utilities.helpers.stringToBytes(request), null).actionPerformed(e);
    }

}








