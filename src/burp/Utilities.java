package burp;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.text.NumberFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

class ConfigMenu implements Runnable, MenuListener, IExtensionStateListener{
    private JMenu menuButton;

    ConfigMenu() {
        Utilities.callbacks.registerExtensionStateListener(this);
    }

    public void run()
    {
        menuButton = new JMenu("Param Miner");
        menuButton.addMenuListener(this);
        JMenuBar burpMenuBar = Utilities.getBurpFrame().getJMenuBar();
        burpMenuBar.add(menuButton);
    }

    public void menuSelected(MenuEvent e) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run(){
                Utilities.globalSettings.showSettings();
            }
        });
    }

    public void menuDeselected(MenuEvent e) { }

    public void menuCanceled(MenuEvent e) { }

    public void extensionUnloaded() {
        JMenuBar jMenuBar = Utilities.getBurpFrame().getJMenuBar();
        jMenuBar.remove(menuButton);
        jMenuBar.repaint();
    }
}

interface ConfigListener {
    void valueUpdated(String value);
}

class ConfigurableSettings {
    private LinkedHashMap<String, String> settings;
    private NumberFormatter onlyInt;

    private HashMap<String, ConfigListener> callbacks = new HashMap<>();

    public void registerListener(String key, ConfigListener listener) {
        callbacks.put(key, listener);
    }

    ConfigurableSettings() {
        settings = new LinkedHashMap<>();
        put("thread pool size", 8);

        put("use key", true);
        put("key method", true);
        put("key status", true);
        put("key content-type", true);
        put("key server", true);
        put("key header names", false);

        // smuggle-scan specific
        put("try chunk-truncate", true);
        put("try timeout-diff", true);
        put("poc: G", true);
        put("poc: headerConcat", true);
        put("poc: bodyConcat", true);
        put("poc: collab", true);
        put("poc: collab-header", true);

        put("avoid rescanning vulnerable hosts", false);

        for(String key: settings.keySet()) {
            //Utilities.callbacks.saveExtensionSetting(key, null); // purge saved settings
            String value = Utilities.callbacks.loadExtensionSetting(key);
            if (Utilities.callbacks.loadExtensionSetting(key) != null) {
                putRaw(key, value);
            }
        }

        NumberFormat format = NumberFormat.getInstance();
        onlyInt = new NumberFormatter(format);
        onlyInt.setValueClass(Integer.class);
        onlyInt.setMinimum(-1);
        onlyInt.setMaximum(Integer.MAX_VALUE);
        onlyInt.setAllowsInvalid(false);

    }

    private ConfigurableSettings(ConfigurableSettings base) {
        settings = new LinkedHashMap<>(base.settings);
        onlyInt = base.onlyInt;
    }

    void printSettings() {
        for(String key: settings.keySet()) {
            Utilities.out(key + ": "+settings.get(key));
        }
    }

    static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

    private String encode(Object value) {
        String encoded;
        if (value instanceof Boolean) {
            encoded = String.valueOf(value);
        }
        else if (value instanceof Integer) {
            encoded = String.valueOf(value);
        }
        else {
            encoded = "\"" + ((String) value).replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        }
        return encoded;
    }

    private void putRaw(String key, String value) {
        settings.put(key, value);
        ConfigListener callback = callbacks.getOrDefault(key, null);
        if (callback != null) {
            callback.valueUpdated(value);
        }
    }

    private void put(String key, Object value) {
        putRaw(key, encode(value));
    }

    String getString(String key) {
        String decoded = settings.get(key);
        decoded = decoded.substring(1, decoded.length()-1).replace("\\\"", "\"").replace("\\\\", "\\");
        return decoded;
    }

    int getInt(String key) {
        return Integer.parseInt(settings.get(key));
    }

    boolean getBoolean(String key) {
        String val = settings.get(key);
        if ("true".equals(val)) {
            return true;
        }
        else if ("false".equals(val)){
            return false;
        }
        throw new RuntimeException("Not boolean or not found: "+key);
    }

    private String getType(String key) {
        String val = settings.get(key);
        if (val.equals("true") || val.equals("false")) {
            return "boolean";
        }
        else if (val.startsWith("\"")) {
            return "string";
        }
        else {
            return "number";
        }
    }

    ConfigurableSettings showSettings() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(0, 2));

        HashMap<String, Object> configured = new HashMap<>();

        for(String key: settings.keySet()) {
            String type = getType(key);
            panel.add(new JLabel("\n"+key+": "));

            if (type.equals("boolean")) {
                JCheckBox box = new JCheckBox();
                box.setSelected(getBoolean(key));
                panel.add(box);
                configured.put(key, box);
            }
            else if (type.equals("number")){
                JTextField box = new JFormattedTextField(onlyInt);
                box.setText(String.valueOf(getInt(key)));
                panel.add(box);
                configured.put(key, box);
            }
            else {
                JTextField box = new JTextField(getString(key));
                panel.add(box);
                configured.put(key, box);
            }
        }

        int result = JOptionPane.showConfirmDialog(Utilities.getBurpFrame(), panel, "Attack Config", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            for(String key: configured.keySet()) {
                Object val = configured.get(key);
                if (val instanceof JCheckBox) {
                    val = ((JCheckBox) val).isSelected();
                }
                else if (val instanceof JFormattedTextField) {
                    val = Integer.parseInt(((JFormattedTextField) val).getText().replaceAll("[^-\\d]", ""));
                }
                else {
                    val = ((JTextField) val).getText();
                }
                put(key, val);
                Utilities.callbacks.saveExtensionSetting(key, encode(val));
            }

            return new ConfigurableSettings(this);
        }

        return null;
    }



}

class Utilities {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    static final boolean DEBUG = false;

    static final byte CONFIRMATIONS = 5;

    static final boolean CACHE_ONLY = false;

    static AtomicBoolean unloaded = new AtomicBoolean(false);


    static final byte PARAM_HEADER = 7;

    static IBurpExtenderCallbacks callbacks;
    static IExtensionHelpers helpers;
    static HashSet<String> phpFunctions = new HashSet<>();
    static ArrayList<String> paramNames = new ArrayList<>();
    static HashSet<String> boringHeaders = new HashSet<>();
    static Set<String> reportedParams = ConcurrentHashMap.newKeySet();

    private static final String CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz"; // ABCDEFGHIJKLMNOPQRSTUVWXYZ
    private static final String START_CHARSET = "ghijklmnopqrstuvwxyz";
    static Random rnd = new Random();

    static ConfigurableSettings globalSettings;

    static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

    Utilities(final IBurpExtenderCallbacks incallbacks) {
        callbacks = incallbacks;
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();

        globalSettings = new ConfigurableSettings();
        globalSettings.printSettings();
    }

    static boolean isBurpPro() {
        return callbacks.getBurpVersion()[0].contains("Professional");
    }

    static String getNameFromType(byte type) {
        switch (type) {
            case IParameter.PARAM_BODY:
                return "body";
            case IParameter.PARAM_URL:
                return "url";
            case IParameter.PARAM_COOKIE:
                return "cookie";
            case IParameter.PARAM_JSON:
                return "json";
            case Utilities.PARAM_HEADER:
                return "header";
            default:
                return "unknown";
        }
    }

    static int generate(int seed, int count, List<String> accumulator)
    {

        int num = seed;
        int limit = seed + count;
        for (; num < limit; num++) {
            String word = num2word(num);
            if(word != null)
            {
                accumulator.add(word);
            }
            else
            {
                limit++;
            }
        }
        return num;
    }

    private static String num2word(int num)
    {
        String number = num2String(num);
        if (number.contains("0"))
        {
            return null;
        }
        return number;
    }

    private static char[] DIGITS = {'0', 'a' , 'b' ,
            'c' , 'd' , 'e' , 'f' , 'g' , 'h' ,
            'i' , 'j' , 'k' , 'l' , 'm' , 'n' ,
            'o' , 'p' , 'q' , 'r' , 's' , 't' ,
            'u' , 'v' , 'w' , 'x' , 'y' , 'z'};

    private static String num2String(int i) {

        if(i < 0)
        {
            throw new IllegalArgumentException("+ve integers only please");
        }

        char buf[] = new char[7];
        int charPos = 6;

        i = -i;

        while (i <= -DIGITS.length) {
            buf[charPos--] = DIGITS[-(i % DIGITS.length)];
            i = i / DIGITS.length;
        }
        buf[charPos] = DIGITS[-i];

        return new String(buf, charPos, (7 - charPos));
    }


    static String filter(String input, String safeChars) {
        StringBuilder out = new StringBuilder(input.length());
        HashSet<Character> charset = new HashSet<>();
        charset.addAll(safeChars.chars().mapToObj(c -> (char) c).collect(Collectors.toList()));
        for(char c: input.toCharArray()) {
            if (charset.contains(c)) {
                out.append(c);
            }
        }
        return out.toString();
    }

    static boolean invertable(String value) {
        return !value.equals(invert(value));
    }

    static Object invert(String value) {
        if (value != null) {
            if (value.equals("true")) {
                return false;
            } else if (value.equals("false")) {
                return true;
            }
            else if (value.equals("1")) {
                return 0;
            }
            else if (value.equals("0")) {
                return 1;
            }
        }
        return value;
    }

    static String randomString(int len) {
        StringBuilder sb = new StringBuilder(len);
        sb.append(START_CHARSET.charAt(rnd.nextInt(START_CHARSET.length())));
        for (int i = 1; i < len; i++)
            sb.append(CHARSET.charAt(rnd.nextInt(CHARSET.length())));
        return sb.toString();
    }

    static String mangle(String seed) {
        Random seededRandom = new Random(seed.hashCode());
        StringBuilder sb = new StringBuilder(7);
        sb.append(START_CHARSET.charAt(seededRandom.nextInt(START_CHARSET.length())));
        for (int i = 1; i < 8; i++)
            sb.append(CHARSET.charAt(seededRandom.nextInt(CHARSET.length())));
        return sb.toString();
    }

    static void out(String message) {
        stdout.println(message);
    }
    static void err(String message) {
        stderr.println(message);
    }

    static void log(String message) {
        if (DEBUG) {
            stdout.println(message);
        }
    }

    static String getBody(byte[] response) {
        if (response == null) { return ""; }
        int bodyStart = Utilities.getBodyStart(response);
        String body = Utilities.helpers.bytesToString(Arrays.copyOfRange(response, bodyStart, response.length));
        return body;
    }

    static String generateCanary() {
        return randomString(4+rnd.nextInt(7)) + Integer.toString(rnd.nextInt(9));
    }

    private static String sensibleURL(URL url) {
        String out = url.toString();
        if (url.getDefaultPort() == url.getPort()) {
            out = out.replaceFirst(":" + Integer.toString(url.getPort()), "");
        }
        return out;
    }

    static URL getURL(byte[] request, IHttpService service) {
        URL url;
        try {
            url = new URL(service.getProtocol(), service.getHost(), service.getPort(), getPathFromRequest(request));
        } catch (java.net.MalformedURLException e) {
            url = null;
        }
        return url;
    }

    static URL getURL(IHttpRequestResponse request) {
        return getURL(request.getRequest(), request.getHttpService());
    }

    static int parseArrayIndex(String key) {
        try {
            if (key.length() > 2 && key.startsWith("[") && key.endsWith("]")) {
                return Integer.parseInt(key.substring(1, key.length() - 1));
            }
        }
        catch (NumberFormatException e) {

        }
        return -1;
    }

    static boolean mightBeFunction(String value) {
        return phpFunctions.contains(value);
    }

    // records from the first space to the second space
    static String getPathFromRequest(byte[] request) {
        int i = 0;
        boolean recording = false;
        String path = "";
        while (i < request.length) {
            byte x = request[i];

            if (recording) {
                if (x != ' ') {
                    path += (char) x;
                } else {
                    break;
                }
            } else {
                if (x == ' ') {
                    recording = true;
                }
            }
            i++;
        }
        return path;
    }

    static String getExtension(byte[] request) {
        String url = getPathFromRequest(request);
        int query_start = url.indexOf('?');
        if (query_start == -1) {
            query_start = url.length();
        }
        url = url.substring(0, query_start);
        int last_dot = url.lastIndexOf('.');
        if (last_dot == -1) {
            return "";
        }
        else {
            return url.substring(last_dot);
        }
    }



    static IHttpRequestResponse fetchFromSitemap(URL url) {
        IHttpRequestResponse[] pages = callbacks.getSiteMap(sensibleURL(url));
        for (IHttpRequestResponse page : pages) {
            if (page.getResponse() != null) {
                if (url.equals(getURL(page))) {
                    return page;
                }
            }
        }
        return null;
    }

    static int countByte(byte[] response, byte match) {
        int count = 0;
        int i = 0;
        while (i < response.length) {
            if (response[i] == match) {
                count +=1 ;
            }
            i += 1;
        }
        return count;
    }

    static int countMatches(byte[] response, byte[] match) {
        int matches = 0;
        if (match.length < 4) {
            return matches;
        }

        int start = 0;
        // Utilities.out("#"+response.length);
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches += 1;
            start += match.length;
        }

        return matches;
    }

    static byte[] replace(byte[] request, byte[] find, byte[] replace) {
        return replace(request, find, replace, -1);
    }

    static byte[] replaceFirst(byte[] request, byte[] find, byte[] replace) {
        return replace(request, find, replace, 1);
    }

    private static byte[] replace(byte[] request, byte[] find, byte[] replace, int limit) {
        List<int[]> matches = getMatches(request, find, -1);
        if (limit != -1) {
            matches = matches.subList(0, limit);
        }
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            for (int i=0;i<matches.size();i++) {
                if (i == 0) {
                    outputStream.write(Arrays.copyOfRange(request, 0, matches.get(i)[0]));
                }
                else {
                    outputStream.write(Arrays.copyOfRange(request, matches.get(i-1)[1], matches.get(i)[0]));
                }
                outputStream.write(replace);

                if (i==matches.size()-1) {
                    outputStream.write(Arrays.copyOfRange(request, matches.get(i)[1], request.length));
                    break;
                }
            }
            request = outputStream.toByteArray();
        } catch (IOException e) {
            return null;
        }

        return request;
    }



    static byte[] appendToQueryzzz(byte[] request, String suffix) {
        if (suffix == null || suffix.equals("")) {
            return request;
        }

        int lineEnd = 0;
        while (lineEnd < request.length && request[lineEnd++] != '\n') {
        }

        int queryStart = 0;
        while (queryStart < lineEnd && request[queryStart++] != '?') {
        }

        if (queryStart >= lineEnd) {
            suffix = "?" + suffix;
        }
        else {
            suffix = "&";
        }

        return replace(request, " HTTP/1.1".getBytes(), (suffix+" HTTP/1.1").getBytes());
    }


    // does not update content length
    static byte[] setBody(byte[] req, String body) {
        try {
            ByteArrayOutputStream synced = new ByteArrayOutputStream();
            synced.write(Arrays.copyOfRange(req, 0, Utilities.getBodyStart(req)));
            synced.write(body.getBytes());
            return  synced.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    static byte[] appendToQuery(byte[] request, String suffix) {
        String url = getPathFromRequest(request);
        if(url.contains("?")) {
            if (url.indexOf("?") == url.length()-1) {
                // add suffix
            }
            else {
                suffix = "&" + suffix;
            }
        }
        else {
            suffix = "?" + suffix;
        }

        return replaceFirst(request, url.getBytes(), (url+suffix).getBytes());
    }

    static byte[] appendToPath(byte[] request, String suffix) {
        if (suffix == null || suffix.equals("")) {
            return request;
        }

        int i = 0;
        while (i < request.length && request[i++] != '\n') {
        }

        int j = 0;
        while (j < i && request[j++] != '?') {
        }

        if(j >= i) {
            request = replace(request, " HTTP/1.1".getBytes(), (suffix+" HTTP/1.1").getBytes());
        }
        else {
            request = replace(request, "?".getBytes(), (suffix+"?").getBytes()); // fixme replace can't handle single-char inputs
        }

        return request;
    }

    static List<int[]> getMatches(byte[] response, byte[] match, int giveUpAfter) {
        if (giveUpAfter == -1) {
            giveUpAfter = response.length;
        }

        List<int[]> matches = new ArrayList<>();

//        if (match.length < 4) {
//            return matches;
//        }

        int start = 0;
        while (start < giveUpAfter) {
            start = helpers.indexOf(response, match, true, start, giveUpAfter);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }

        return matches;
    }

    public static void doActiveScan(IHttpRequestResponse req, int[] offsets) {
        String host = helpers.analyzeRequest(req).getUrl().getHost();
        int port = helpers.analyzeRequest(req).getUrl().getPort();
        boolean useHTTPS = helpers.analyzeRequest(req).getUrl().toString().startsWith("https");
        ArrayList<int[]> offsetList = new ArrayList<>();
        offsetList.add(offsets);
        try {
            callbacks.doActiveScan(
                    host, port, useHTTPS, req.getRequest(), offsetList
            );
        } catch (IllegalArgumentException e) {
            Utilities.err("Couldn't scan, bad insertion points: "+Arrays.toString(offsetList.get(0)));
        }
    }

    static String fuzzSuffix() {
        if(Utilities.globalSettings.getBoolean("fuzz detect")) {
            return "<a`'\"${{\\"; // <a
        }
        else {
            return "";
        }
    }

    static String toCanary(String payload) {
        return "wrtqva" + mangle(payload);
    }

    public static int getBodyStart(byte[] response) {
        int i = 0;
        int newlines_seen = 0;
        while (i < response.length) {
            byte x = response[i];
            if (x == '\n') {
                newlines_seen++;
            } else if (x != '\r') {
                newlines_seen = 0;
            }

            if (newlines_seen == 2) {
                break;
            }
            i += 1;
        }


        while (i < response.length && (response[i] == ' ' || response[i] == '\n' || response[i] == '\r')) {
            i++;
        }

        return i;
    }

    static String getStartType(byte[] response) {
        int i = getBodyStart(response);

        String start = "";
        if (i == response.length) {
            start = "[blank]";
        }
        else if (response[i] == '<') {
            while (i < response.length && (response[i] != ' ' && response[i] != '\n' && response[i] != '\r' && response[i] != '>')) {
                start += (char) (response[i] & 0xFF);
                i += 1;
            }
        }
        else {
            start = "text";
        }

        return start;
    }

    public static String getHeader(byte[] request, String header) {
        int[] offsets = getHeaderOffsets(request, header);
        if (offsets == null) {
            return "";
        }
        String value = helpers.bytesToString(Arrays.copyOfRange(request, offsets[1], offsets[2]));
        return value;
    }

    public static boolean containsBytes(byte[] request, byte[] value) {
        return helpers.indexOf(request, value, false, 1, request.length - 1) != -1;
    }

    public static byte[] setHeader(byte[] request, String header, String value) {
        int[] offsets = getHeaderOffsets(request, header);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write( Arrays.copyOfRange(request, 0, offsets[1]));
            outputStream.write(helpers.stringToBytes(value));
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.length));
            return outputStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Req creation unexpectedly failed");
        } catch (NullPointerException e) {
            Utilities.out("header locating fail: "+header);
            Utilities.out("'"+helpers.bytesToString(request)+"'");
            throw new RuntimeException("Can't find the header: "+header);
        }
    }

    public static String encodeJSON(String input) {
        input = input.replace("\\", "\\\\");
        input = input.replace("\"", "\\\"");
        return input;
    }

    public static int[] getHeaderOffsets(byte[] request, String header) {
        int i = 0;
        int end = request.length;
        while (i < end) {
            int line_start = i;
            while (i < end && request[i++] != ' ') {
            }
            byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
            int headerValueStart = i;
            while (i < end && request[i++] != '\n') {
            }
            if (i == end) {
                break;
            }

            String header_str = helpers.bytesToString(header_name);

            if (header.equals(header_str)) {
                int[] offsets = {line_start, headerValueStart, i - 2};
                return offsets;
            }

            if (i + 2 < end && request[i] == '\r' && request[i + 1] == '\n') {
                break;
            }
        }
        return null;
    }

    // todo refactor to use getHeaderOffsets
    // fixme fails if the modified header is the last header
    public static byte[] addOrReplaceHeader(byte[] request, String header, String value) {
        try {
            int i = 0;
            int end = request.length;
            while (i < end && request[i++] != '\n') {
            }
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            while (i < end) {
                int line_start = i;
                while (i < end && request[i++] != ' ') {
                }
                byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
                int headerValueStart = i;
                while (i < end && request[i++] != '\n') {
                }
                if (i == end) {
                    break;
                }

                if(i+2<end && request[i] == '\r' && request[i+1] == '\n') {
                    outputStream.write(Arrays.copyOfRange(request, 0, i));
                    outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n"));
                    outputStream.write(Arrays.copyOfRange(request, i, end));
                    return outputStream.toByteArray();
                }

                String header_str = helpers.bytesToString(header_name);

                if (header.equals(header_str)) {

                    outputStream.write(Arrays.copyOfRange(request, 0, headerValueStart));
                    outputStream.write(helpers.stringToBytes(value));
                    outputStream.write(Arrays.copyOfRange(request, i-2, end));
                    return outputStream.toByteArray();
                }
            }
            outputStream.write(Arrays.copyOfRange(request, 0, end-2));
            outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n\r\n"));
            return outputStream.toByteArray();

        } catch (IOException e) {
            throw new RuntimeException("Req creation unexpectedly failed");
        }
    }

    static boolean isResponse(byte[] data) {
        byte[] start = Arrays.copyOfRange(data, 0, 4);
        return (helpers.bytesToString(start).equals("HTTP/"));
    }

    public static byte[] fixContentLength(byte[] request) {
        if (countMatches(request, helpers.stringToBytes("Content-Length: ")) > 0) {
            int start = Utilities.getBodyStart(request);
            int contentLength = request.length - start;
            return setHeader(request, "Content-Length", Integer.toString(contentLength));
        }
        else {
            return request;
        }
    }

//    static byte[] addBulkParams(byte[] request, String name, String value, byte type) {
//
//    }

    static List<IParameter> getExtraInsertionPoints(byte[] request) { //
        List<IParameter> params = new ArrayList<>();
        int end = getBodyStart(request);
        int i = 0;
        while(i < end && request[i++] != ' ') {} // walk to the url start
        while(i < end) {
            byte c = request[i];
            if (c == ' ' ||
                    c == '?' ||
                    c == '#') {
                break;
            }
            i++;
        }

        params.add(new PartialParam("path", i, i));
        while(request[i++] != '\n' && i < end) {}

        String[] to_poison = {"User-Agent", "Referer", "X-Forwarded-For", "Host"};
        while(i<end) {
            int line_start = i;
            while(i < end && request[i++] != ' ') {}
            byte[] header_name = Arrays.copyOfRange(request, line_start, i-2);
            int headerValueStart = i;
            while(i < end && request[i++] != '\n') {}
            if (i == end) { break; }

            String header_str = helpers.bytesToString(header_name);
            for (String header: to_poison) {
                if (header.equals(header_str)) {
                    params.add(new PartialParam(header, headerValueStart, i-2));
                }
            }
        }


        return params;
    }

    static boolean isHTTP(URL url) {
        String protocol = url.getProtocol().toLowerCase();
        return "https".equals(protocol);
    }

    static IHttpRequestResponse highlightRequestResponse(IHttpRequestResponse attack, String responseHighlight, String requestHighlight, IScannerInsertionPoint insertionPoint) {
        List<int[]> requestMarkers = new ArrayList<>(1);
        if (requestHighlight != null && requestHighlight.length() > 2) {
            requestMarkers.add(insertionPoint.getPayloadOffsets(requestHighlight.getBytes()));
        }

        List<int[]> responseMarkers = new ArrayList<>(1);
        if (responseHighlight != null) {
            responseMarkers = getMatches(attack.getResponse(), responseHighlight.getBytes(), -1);
        }

        attack = callbacks.applyMarkers(attack, requestMarkers, responseMarkers);
        return attack;
    }

    static IHttpRequestResponse attemptRequest(IHttpService service, byte[] req) {
        if(unloaded.get()) {
            Utilities.out("Extension unloaded - aborting attack");
            throw new RuntimeException("Extension unloaded");
        }

        IHttpRequestResponse result = null;

        for(int attempt=1; attempt<3; attempt++) {
            try {
                result = callbacks.makeHttpRequest(service, req);
            } catch(RuntimeException e) {
                Utilities.log(e.toString());
                Utilities.log("Critical request error, retrying...");
                continue;
            }

            if (result.getResponse() == null) {
                Utilities.log("Req failed, retrying...");
                //requestResponse.setResponse(new byte[0]);
            }
            else {
                break;
            }
        }

        if (result.getResponse() == null) {
            Utilities.log("Req failed multiple times, giving up");
        }

        return result;
    }

    static String encodeParam(String payload) {
        return payload.replace("%", "%25").replace("\u0000", "%00").replace("&", "%26").replace("#", "%23").replace("\u0020", "%20").replace(";", "%3b").replace("+", "%2b").replace("\n", "%0A").replace("\r", "%0d");
    }
}

class PartialParam implements IParameter {

    private int valueStart, valueEnd;
    private String name;

    PartialParam(String name, int valueStart, int valueEnd) {
        this.name = name;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
    }

    @Override
    public byte getType() {
        return IParameter.PARAM_COOKIE;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return null;
    }

    @Override
    public int getNameStart() {
        return 0;
    }

    @Override
    public int getNameEnd() {
        return 0;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }
}


