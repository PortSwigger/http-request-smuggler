package burp;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;

public class SuggestAttack implements IContextMenuFactory {

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        ArrayList<JMenuItem> options = new ArrayList<>();

        // todo add support for click on the scanner issue itself?
        if (invocation != null && invocation.getSelectedMessages()[0] != null) {

            IHttpRequestResponse message = invocation.getSelectedMessages()[0];
            String request = new String(message.getRequest());
            String headers = Utils.getHeaders(request);

            if (headers.contains("chunked")) {
                JMenuItem probeButton = new JMenuItem("Smuggle attack");
                probeButton.addActionListener(new LaunchSuggestedAttack(message));
                options.add(probeButton);
            }

        }
        return options;
    }

}

class LaunchSuggestedAttack implements ActionListener {

    private IHttpRequestResponse message;

    LaunchSuggestedAttack(IHttpRequestResponse message) {
        this.message = message;
    }

    @Override
    public void actionPerformed(ActionEvent e) {

        String PAYLOAD = "\r\n1\r\nZ\r\nQ\r\n\r\n";
        String request = new String(message.getRequest());
        String script;

        if (request.contains(PAYLOAD)) {
            // this is CL.TE
            script = Utilities.getResource("/CL-TE.py");
            request = request.replaceFirst(PAYLOAD, "\r\n0\r\n\r\n");
        }
        else {
            // this is either a normal chunked request, or TE.CL
            script = Utilities.getResource("/TE-CL.py");
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

        new TurboIntruderFrame(message, new int[]{}, script, Utilities.helpers.stringToBytes(request)).actionPerformed(e);
    }

}








