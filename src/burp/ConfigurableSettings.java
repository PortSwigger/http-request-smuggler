package burp;

import javax.swing.*;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import javax.swing.text.NumberFormatter;
import java.awt.*;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

class ConfigMenu implements Runnable, MenuListener, IExtensionStateListener{
    private JMenu menuButton;

    ConfigMenu() {
        Utilities.callbacks.registerExtensionStateListener(this);
    }

    public void run()
    {
        menuButton = new JMenu(BurpExtender.name);
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
    static private LinkedHashMap<String, String> settings = new LinkedHashMap<>();
    static private LinkedHashMap<String, String> defaultSettings = new LinkedHashMap<>();
    private NumberFormatter onlyInt;

    private HashMap<String, ConfigListener> callbacks = new HashMap<>();

    public void registerListener(String key, ConfigListener listener) {
        callbacks.put(key, listener);
    }

    void registerSetting(String key, Object value) {
        if (settings.containsKey(key)) {
            return;
        }

        defaultSettings.put(key, encode(value));
        String oldValue = Utilities.callbacks.loadExtensionSetting(key);
        if (oldValue != null) {
            putRaw(key, oldValue);
            return;
        }

        putRaw(key, encode(value));
    }

    ConfigurableSettings() {
        registerSetting("thread pool size", 8);
        registerSetting("timeout", 10);
        registerSetting("use key", true);
        registerSetting("key method", true);
        registerSetting("key status", true);
        registerSetting("key content-type", true);
        registerSetting("key server", true);
        registerSetting("key header names", false);

        // smuggle-scan specific
        //registerSetting("try chunk-truncate", true);
        //registerSetting("try timeout-diff", true);
        registerSetting("skip straight to poc", false);
        registerSetting("poc: G", false);
        registerSetting("poc: headerConcat", false);
        registerSetting("poc: bodyConcat", false);
        registerSetting("poc: collab", false);
        registerSetting("poc: collab-header", false);
        registerSetting("poc: collab-XFO-header", false);
        registerSetting("poc: collab-abs", false);
        registerSetting("poc: collab-at", false);
        registerSetting("poc: collab-blind", false);

        registerSetting("poc-collab domain", "manual-collab-domain-here");
        registerSetting("use turbo for autopoc", true);

        registerSetting("skip vulnerable hosts", false);
        registerSetting("skip obsolete permutations", false);
        registerSetting("only report exploitable", false);
        registerSetting("risky mode", false);
        registerSetting("pad everything", false);
        registerSetting("filter", "");

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
        new ConfigMenu().run();
    }

    public void setDefaultSettings() {
        for (String key: settings.keySet()) {
            putRaw(key, defaultSettings.get(key));
        }
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
        throw new RuntimeException();
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
        panel.setLayout(new GridLayout(0, 6));
        panel.setSize(800, 800);

        HashMap<String, Object> configured = new HashMap<>();
        JButton buttonResetSettings = new JButton("Reset Settings");

        for(String key: settings.keySet()) {
            String type = getType(key);
            JLabel label = new JLabel("\n"+key+": ");
            if (!settings.get(key).equals(defaultSettings.get(key))) {
                label.setForeground(Color.magenta);
            }
            panel.add(label);

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
                String value = getString(key);
                JTextField box = new JTextField(value, value.length());
                box.setColumns(1);
                panel.add(box);
                configured.put(key, box);
            }
        }

        panel.add(new JLabel(""));
        panel.add(new JLabel(""));
        panel.add(buttonResetSettings);
        buttonResetSettings.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                Utilities.out("Discarding settings...");
                for(String key: settings.keySet()) {
                    Utilities.callbacks.saveExtensionSetting(key, null); // purge saved settings
                }
                setDefaultSettings();
                //BulkScanLauncher.registerDefaults();
                JComponent comp = (JComponent) e.getSource();
                Window win = SwingUtilities.getWindowAncestor(comp);
                win.dispose();

            }
        } );

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
