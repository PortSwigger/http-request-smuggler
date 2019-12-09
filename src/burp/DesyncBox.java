package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class DesyncBox {

    static byte[] applyDesync(byte[] request, HashMap<String, Boolean> settings) {
        
        if (settings.containsKey("underjoin1")) {
            request = Utilities.replace(request, "Transfer-Encoding".getBytes(), "Transfer_Encoding".getBytes());
        } else if (settings.containsKey("spacejoin1")) {
            request = Utilities.replace(request, "Transfer-Encoding".getBytes(), "Transfer Encoding".getBytes());
        }
        else if (settings.containsKey("space1")) {
            request = Utilities.replace(request, "Transfer-Encoding".getBytes(), "Transfer-Encoding ".getBytes());
        }
        else if (settings.containsKey("nameprefix1")) {
            request = Utilities.replace(request, "Transfer-Encoding".getBytes(), " Transfer-Encoding".getBytes());
        }
        else if (settings.containsKey("valueprefix1")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:  ".getBytes());
        }
        else if (settings.containsKey("nospace1")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:".getBytes());
        }
//        else if (settings.containsKey("tabprefix1")) {
//            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\t".getBytes());
//        }
//        else if (settings.containsKey("vertprefix1")) {
//            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\u000B".getBytes());
//        }
        else if (settings.containsKey("commaCow")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: chunked, identity".getBytes());
        }
        else if (settings.containsKey("cowComma")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: identity, ".getBytes());
        }
        else if (settings.containsKey("contentEnc")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Content-Encoding: ".getBytes());
        }

        else if (settings.containsKey("linewrapped1")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding:\n ".getBytes());
        } else if (settings.containsKey("gareth1")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding\n : ".getBytes());
        } else if (settings.containsKey("quoted")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: \"chunked\"".getBytes());
        } else if (settings.containsKey("aposed")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: 'chunked'".getBytes());
        } else if (settings.containsKey("badwrap")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            request = Utilities.replace(request, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\n Transfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("badsetupCR")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            request = Utilities.replace(request, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\nFooz: bar\rTransfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("badsetupLF")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            request = Utilities.replace(request, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\nFooz: bar\nTransfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("vertwrap")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: \n\u000B".getBytes());
        } else if (settings.containsKey("tabwrap")) {
            request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: \n\t".getBytes());
        } else if (settings.containsKey("dualchunk")) {
            request = Utilities.addOrReplaceHeader(request, "Transfer-encoding", "identity");
        } else if (settings.containsKey("lazygrep")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunk");
        } else if (settings.containsKey("multiCase")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "TrAnSFer-EnCODinG: cHuNkeD");
        } else if (settings.containsKey("UPPERCASE")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "TRANSFER-ENCODING: CHUNKED");
        } else if (settings.containsKey("0dwrap")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Foo: bar".getBytes());
            request = Utilities.replace(request, "HTTP/1.1\r\n".getBytes(), "HTTP/1.1\r\nFoo: bar\r\n\rTransfer-Encoding: chunked\r\n".getBytes());
        } else if (settings.containsKey("0dsuffix")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r");
        } else if (settings.containsKey("tabsuffix")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\t");
        } else if (settings.containsKey("revdualchunk")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked");
        } else if (settings.containsKey("0dspam")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer\r-Encoding: chunked");
        } else if (settings.containsKey("bodysplit")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "X: y");
            request = Utilities.addOrReplaceHeader(request, "Foo", "barzxaazz");
            request = Utilities.replace(request, "barzxaazz", "barn\n\nTransfer-Encoding: chunked");
        } else if (settings.containsKey("connection")) {
            request = Utilities.addOrReplaceHeader(request, "Connection", "Transfer-Encoding");
        } else if (settings.containsKey("nested")) {
            request = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: cow chunked bar");
        }

        for (int i: getSpecialChars()) {
            if (settings.containsKey("spacefix1:"+i)) {
                request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), ("Transfer-Encoding:"+(char) i).getBytes());
            }
        }

        for (int i: getSpecialChars()) {
            if (settings.containsKey("prefix1:"+i)) {
                request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), ("Transfer-Encoding: "+(char) i).getBytes());
            }
        }

        for (int i: getSpecialChars()) {
            if (settings.containsKey("suffix1:"+i)) {
                request = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), ("Transfer-Encoding: chunked"+(char) i).getBytes());
            }
        }

        if (settings.containsKey("spaceFF")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transfer-Encoding:".getBytes());
                encoded.write((byte) 0xFF);
                request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }
        if (settings.containsKey("unispace")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transfer-Encoding:".getBytes());
                encoded.write((byte) 0xa0);
                request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }

        if (settings.containsKey("accentTE")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transf".getBytes());
                encoded.write((byte) 0x82);
                encoded.write("r-Encoding: ".getBytes());
                request = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }
        if (settings.containsKey("accentCH")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write("Transfer-Encoding: ch".getBytes());
                encoded.write((byte) 0x96);
                request = Utilities.replace(request, "Transfer-Encoding: chu".getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }
        return request;
    }

    static ArrayList<Integer> getSpecialChars() {
        ArrayList<Integer> chars = new ArrayList<>();
//        for (int i=0;i<32;i++) {
//            chars.add(i);
//        }

        chars.add(0); // null
        chars.add(9); // tab
        chars.add(11); // vert tab
        chars.add(12); // form feed
        chars.add(13); // \r
        chars.add(127);
        return chars;
    }
}
