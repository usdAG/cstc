package de.usd.cstchef.operations.encrpytion;

import java.security.Provider;
import java.security.Security;
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
					}
					this.algos.put(cipherName, info);
				}
			}
		}
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
