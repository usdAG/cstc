package de.usd.cstchef;

public class FilterState {
    private int incomingFilterMask;
    private int outgoingFilterMask;
    private int formatFilterMask;

    FilterState(int incomingFilterMask, int outgoingFilterMask, int formatFilterMask){
        this.incomingFilterMask = incomingFilterMask;
        this.outgoingFilterMask = outgoingFilterMask;
        this.formatFilterMask = formatFilterMask;
    }

    public boolean shouldProcess(int tool, BurpOperation operation) {
        switch(operation){
            case INCOMING: return (this.incomingFilterMask & tool) != 0;
            case OUTGOING: return (this.incomingFilterMask & tool) != 0;
            case FORMAT: return (this.incomingFilterMask & tool) != 0;
            default: return false;
        }
    }

    public void setFilterMask(int filterMask, BurpOperation operation) {
        switch(operation){
            case INCOMING: incomingFilterMask = filterMask;
            case OUTGOING: outgoingFilterMask = filterMask;
            case FORMAT: formatFilterMask = filterMask;
            default: break;
        }
    }

    public void setFilterMask(int incomingFilterMask, int outgoingFilterMask, int formatFilterMask) {
        this.incomingFilterMask = incomingFilterMask;
        this.outgoingFilterMask = outgoingFilterMask;
        this.formatFilterMask = formatFilterMask;
    }

     public static String translateBurpOperation(BurpOperation operation){
        switch(operation){
            case INCOMING: return "Incoming";
            case OUTGOING: return "Outgoing";
            case FORMAT: return "Formatting";
            default: return new String();
        }
    }

    public enum BurpOperation{
        INCOMING,
        OUTGOING,
        FORMAT
    }
}
