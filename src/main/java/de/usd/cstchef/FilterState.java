package de.usd.cstchef;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import burp.Logger;
import de.usd.cstchef.view.RequestFilterDialog.Filter;

public class FilterState implements Serializable{
    private LinkedHashMap<Filter, Boolean> incomingFilterSettings;
    private LinkedHashMap<Filter, Boolean> outgoingFilterSettings;
    private LinkedHashMap<Filter, Boolean> formatFilterSettings;

    public FilterState(LinkedHashMap<Filter, Boolean> incomingFilterSettings,
            LinkedHashMap<Filter, Boolean> outgoingFilterSettings,
            LinkedHashMap<Filter, Boolean> formatFilterSettings) {
        this.incomingFilterSettings = incomingFilterSettings;
        this.outgoingFilterSettings = outgoingFilterSettings;
        this.formatFilterSettings = formatFilterSettings;
    }

    public FilterState() {
        this(new LinkedHashMap<Filter, Boolean>(), new LinkedHashMap<Filter, Boolean>(),
                new LinkedHashMap<Filter, Boolean>());
    }

    public void setFilterMask(LinkedHashMap<Filter, Boolean> filterMask, BurpOperation operation) {
        switch (operation) {
            case INCOMING:
                incomingFilterSettings = filterMask;
                break;
            case OUTGOING:
                outgoingFilterSettings = filterMask;
                break;
            case FORMAT:
                formatFilterSettings = filterMask;
                break;
            default:
                break;
        }
    }

    public LinkedHashMap<Filter, Boolean> getFilterMask(BurpOperation operation) {
        switch (operation) {
            case INCOMING:
                return incomingFilterSettings;
            case OUTGOING:
                return outgoingFilterSettings;
            case FORMAT:
                return formatFilterSettings;
            default:
                return new LinkedHashMap<Filter, Boolean>();
        }
    }

    public void setFilterMask(LinkedHashMap<Filter, Boolean> incomingFilterMask,
            LinkedHashMap<Filter, Boolean> outgoingFilterMask, LinkedHashMap<Filter, Boolean> formatFilterMask) {
        this.incomingFilterSettings = incomingFilterMask;
        this.outgoingFilterSettings = outgoingFilterMask;
        this.formatFilterSettings = formatFilterMask;
    }

    public static String translateBurpOperation(BurpOperation operation) {
        switch (operation) {
            case INCOMING:
                return "Incoming";
            case OUTGOING:
                return "Outgoing";
            case FORMAT:
                return "Formatting";
            default:
                return new String();
        }
    }

    public boolean shouldProcess(BurpOperation operation) {
        LinkedHashMap<Filter, Boolean> filterSettings;
        int filterMask = 0;
        switch (operation) {
            case INCOMING:
                filterSettings = incomingFilterSettings;
                break;
            case OUTGOING:
                filterSettings = outgoingFilterSettings;
                break;
            case FORMAT:
                filterSettings = formatFilterSettings;
                break;
            default:
                filterSettings = new LinkedHashMap<>();
                break;
        }

        for (Map.Entry<Filter, Boolean> entry : filterSettings.entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();
            if (selected) {
                filterMask |= filter.getValue();
            }
        }
        return filterMask != 0;
    }

    public LinkedHashMap<Filter,Boolean> getIncomingFilterSettings() {
        return this.incomingFilterSettings;
    }

    public void setIncomingFilterSettings(LinkedHashMap<Filter,Boolean> incomingFilterSettings) {
        this.incomingFilterSettings = incomingFilterSettings;
    }

    public LinkedHashMap<Filter,Boolean> getOutgoingFilterSettings() {
        return this.outgoingFilterSettings;
    }

    public void setOutgoingFilterSettings(LinkedHashMap<Filter,Boolean> outgoingFilterSettings) {
        this.outgoingFilterSettings = outgoingFilterSettings;
    }

    public LinkedHashMap<Filter,Boolean> getFormatFilterSettings() {
        return this.formatFilterSettings;
    }

    public void setFormatFilterSettings(LinkedHashMap<Filter,Boolean> formatFilterSettings) {
        this.formatFilterSettings = formatFilterSettings;
    }

    public enum BurpOperation {
        INCOMING,
        OUTGOING,
        FORMAT;

        public String toString(){
            switch(this){
                case INCOMING: return "Incoming";
                case OUTGOING: return "Outgoing";
                case FORMAT: return "Formatting";
                default: return "";
            }
        }
    }
}
