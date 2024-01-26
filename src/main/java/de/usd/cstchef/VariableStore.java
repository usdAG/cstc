package de.usd.cstchef;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;

public class VariableStore {

    private static VariableStore instance;

    private HashMap<String, ByteArray> variables = new HashMap<>();
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

    public synchronized ByteArray getVariable(String name) {
        return this.variables.get(name);
    }

    public synchronized void setVariable(String key, ByteArray value) {
        this.variables.put(key, value);
    }

    public synchronized void removeVariable(String key) {
        this.variables.remove(key);
    }

    public synchronized HashMap<String, ByteArray> getVariables() {
        HashMap<String, ByteArray> variablesCopy = new HashMap<>();

        for (Map.Entry<String, ByteArray> entry : this.variables.entrySet()) {
            ByteArray orig = entry.getValue();
            ByteArray newContent = BurpUtils.subArray(orig, 0, orig.length());
            variablesCopy.put(entry.getKey(), newContent);
        }
        return variablesCopy;
    }

}
