package de.usd.cstchef;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class VariableStore {

	private static VariableStore instance;

	private HashMap<String, byte[]> variables = new HashMap<>();
	private ReentrantLock lock = new ReentrantLock();

	public static VariableStore getInstance() {
		if (VariableStore.instance == null) {
			VariableStore.instance = new VariableStore();
		}
		return VariableStore.instance;
	}

	private VariableStore() {
	}
	
	public void lock() {
		 this.lock.lock();
	}
	
	public void unlock() {
		 this.lock.unlock();
	}
	
	public synchronized byte[] getVariable(String name) {
		return this.variables.get(name);
	}

	public synchronized void setVariable(String key, byte[] value) {
		this.variables.put(key, value);
	}

	public synchronized void removeVariable(String key) {
		this.variables.remove(key);
	}

	public synchronized HashMap<String, byte[]> getVariables() {
		HashMap<String, byte[]> variablesCopy = new HashMap<>();
		
		for (Map.Entry<String, byte[]> entry : this.variables.entrySet()) {
			byte[] orig = entry.getValue();
			byte[] newContent = new byte[orig.length];
			System.arraycopy(orig, 0, newContent, 0, orig.length);
			variablesCopy.put(entry.getKey(), newContent);
		}
		return variablesCopy;
	}

}
