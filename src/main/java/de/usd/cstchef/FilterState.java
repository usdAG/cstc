package de.usd.cstchef;

import java.util.LinkedHashMap;
import java.util.Map;

import de.usd.cstchef.view.RequestFilterDialog.Filter;

public class FilterState {
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

    public enum BurpOperation {
        INCOMING,
        OUTGOING,
        FORMAT
    }
}
