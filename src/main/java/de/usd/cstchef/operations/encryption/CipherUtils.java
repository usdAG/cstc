package de.usd.cstchef.operations.encryption;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;

public class CipherUtils {

    private static CipherUtils instance;

    private HashMap<String, CipherInfo> algos;

    private CipherUtils() {
        algos = new HashMap<>();

        getCipherInfos();
    }

    private void getCipherInfos() {
        for (Provider provider : Security.getProviders()) {
            for (String key : provider.stringPropertyNames()) {
                if (key.startsWith("Cipher")) {
                    String[] parts = key.split(" ");
                    if (parts.length < 2) {
                        continue;
                    }
                    String cipherName = parts[0].substring(7);
                    String type = parts[1];

                    CipherInfo info = algos.getOrDefault(cipherName, new CipherInfo());
                    String property = provider.getProperty(key);

                    if (type.equals("SupportedModes")) {
                        String[] modes = property.split("\\|");
                        info.setModes(modes);
                    } else if (type.equals("SupportedPaddings")) {
                        String[] paddings = property.split("\\|");
                        info.setPaddings(paddings);

                        if(key.equals("Cipher.RSA SupportedPaddings")) {
                            String[] rsaPaddings = {"NOPADDING", "PKCS1PADDING", "OAEPPADDING"};
                            info.setPaddings(rsaPaddings);
                        }
                    }
                    this.algos.put(cipherName, info);
                }
            }
        }
        /*
         * Since JDK 9 the providers no longer list GCM in "SupportedModes";
         * it is only registered as complete transformations such as
         * "Cipher.AES/GCM/NoPadding". Lift GCM out of those keys in a second
         * pass so the unordered property iteration above cannot overwrite it.
         */
        for (Provider provider : Security.getProviders()) {
            for (String key : provider.stringPropertyNames()) {
                if (!key.startsWith("Cipher.") || key.contains(" ")) {
                    continue;
                }
                String[] transformation = key.substring(7).split("/");
                if (transformation.length != 3 || !transformation[1].equalsIgnoreCase("GCM")) {
                    continue;
                }
                CipherInfo info = algos.getOrDefault(transformation[0], new CipherInfo());
                info.addMode("GCM");
                this.algos.put(transformation[0], info);
            }
        }

        // Add info for SM4
        CipherInfo info = new CipherInfo();
        info.setModes(new String[]{"ECB", "CBC", "CTR", "OFB", "CFB", "GCM"});
        info.setPaddings(new String[]{"NOPADDING", "PKCS5PADDING"});
        algos.put("SM4", info);
    }

    public static CipherUtils getInstance() {
        if (instance == null) {
            instance = new CipherUtils();
        }
        return instance;
    }

    public CipherInfo getCipherInfo(String algorithm) {
        return this.algos.getOrDefault(algorithm, new CipherInfo());
    }

    public class CipherInfo {

        private String[] modes;
        private String[] paddings;


        public CipherInfo() {
            this.modes = new String[0];
            this.paddings = new String[0];
        }

        public CipherInfo(String[] modes, String[] paddings) {
            this.modes = modes;
            this.paddings = paddings;
        }

        public String[] getModes() {
            return modes;
        }

        public void setModes(String[] modes) {
            this.modes = modes;
        }

        public void addMode(String mode) {
            for (String existing : this.modes) {
                if (existing.equalsIgnoreCase(mode)) {
                    return;
                }
            }
            this.modes = Arrays.copyOf(this.modes, this.modes.length + 1);
            this.modes[this.modes.length - 1] = mode;
        }

        public String[] getPaddings() {
            return paddings;
        }

        public void setPaddings(String[] paddings) {
            this.paddings = paddings;
        }

        public String toString() {
            StringBuffer buf = new StringBuffer();
            buf.append("Modes: ");
            for (String mode : this.modes) {
                buf.append(mode);
                buf.append("|");
            }
            buf.append(", Paddings: ");
            for (String padding : this.paddings) {
                buf.append(padding);
                buf.append("|");
            }

            return buf.toString();
        }

    }
}
