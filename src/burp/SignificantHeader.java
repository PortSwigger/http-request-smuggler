package burp;

import burp.api.montoya.http.message.HttpHeader;

public class SignificantHeader implements HttpHeader {
    final private String name;
    final private String value;

    public boolean shouldRemoveCL() {
        return removeCL;
    }

    final private boolean removeCL;

    public String getBody() {
        return body;
    }

    final private String body;

    public String getLabel() {
        return label;
    }

    final private String label;

    public boolean shouldKeepOriginal() {
        return keepOriginal;
    }

    final private boolean keepOriginal;

    public boolean keepOriginal() {
        return keepOriginal;
    }

    public SignificantHeader(HttpHeader header) {
        this(header.name(), header.name(), header.value(), false);
    }

    public SignificantHeader(String label, String name, String value, boolean keepOriginal) {
        this.label = label;
        this.name = name;
        this.value = value;
        this.keepOriginal = keepOriginal;
        this.body = "";
        this.removeCL = false;
    }

    public SignificantHeader(String label, String name, String value, String body, boolean removeCL, boolean keepOriginal) {
        this.label = label;
        this.name = name;
        this.value = value;
        this.body = body;
        this.keepOriginal = keepOriginal;
        this.removeCL = removeCL;
    }

    public String name() {
        return name;
    }

    public String value() {
        return value;
    }

    public String toString() {
        return name + ": " + value;
    }
}
