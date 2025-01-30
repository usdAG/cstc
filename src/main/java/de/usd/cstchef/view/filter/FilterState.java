package de.usd.cstchef.view.filter;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import burp.api.montoya.core.ToolType;

public class FilterState implements Serializable{
    @JsonDeserialize(keyUsing = FilterStateDeserializer.class)
    private LinkedHashMap<Filter, Boolean> incomingHttpResponseFilterSettings;
    @JsonDeserialize(keyUsing = FilterStateDeserializer.class)
    private LinkedHashMap<Filter, Boolean> incomingProxyRequestFilterSettings;
    @JsonDeserialize(keyUsing = FilterStateDeserializer.class)
    private LinkedHashMap<Filter, Boolean> outgoingHttpRequestFilterSettings;
    @JsonDeserialize(keyUsing = FilterStateDeserializer.class)
    private LinkedHashMap<Filter, Boolean> outgoingProxyResponseFilterSettings;

    public FilterState(LinkedHashMap<Filter, Boolean> incomingHttpResponseFilterSettings,
            LinkedHashMap<Filter, Boolean> incomingProxyRequestFilterSettings,
            LinkedHashMap<Filter, Boolean> outgoingHttpRequestFilterSettings,
            LinkedHashMap<Filter, Boolean> outgoingProxyResponseFilterSettings) {
        this.incomingHttpResponseFilterSettings = incomingHttpResponseFilterSettings;
        this.incomingProxyRequestFilterSettings = incomingProxyRequestFilterSettings;
        this.outgoingHttpRequestFilterSettings = outgoingHttpRequestFilterSettings;
        this.outgoingProxyResponseFilterSettings = outgoingProxyResponseFilterSettings;
    }

    public FilterState() {
        this(new LinkedHashMap<Filter, Boolean>(), new LinkedHashMap<Filter, Boolean>(),
                new LinkedHashMap<Filter, Boolean>(), new LinkedHashMap<Filter, Boolean>());
    }

    public void setFilterMask(LinkedHashMap<Filter, Boolean> filterMask, BurpOperation operation) {
        switch (operation) {
            case INCOMING_HTTP_RESPONSE:
                incomingHttpResponseFilterSettings = filterMask;
                break;
            case INCOMING_PROXY_REQUEST:
                incomingProxyRequestFilterSettings = filterMask;
                break;
            case OUTGOING_HTTP_REQUEST:
                outgoingHttpRequestFilterSettings = filterMask;
                break;
            case OUTGOING_PROXY_RESPONSE:
                outgoingProxyResponseFilterSettings = filterMask;
                break;
            default:
                break;
        }
    }

    public LinkedHashMap<Filter, Boolean> getFilterMask(BurpOperation operation) {
        switch (operation) {
            case INCOMING_HTTP_RESPONSE:
                return incomingHttpResponseFilterSettings;
            case INCOMING_PROXY_REQUEST:
                return incomingProxyRequestFilterSettings;
            case OUTGOING_HTTP_REQUEST:
                return outgoingHttpRequestFilterSettings;
            case OUTGOING_PROXY_RESPONSE:
                return outgoingProxyResponseFilterSettings;
            default:
                return new LinkedHashMap<Filter, Boolean>();
        }
    }

    public void setFilterMask(LinkedHashMap<Filter, Boolean> incomingHttpResponseFilterMask,
            LinkedHashMap<Filter, Boolean> incomingProxyRequestFilterMask,
            LinkedHashMap<Filter, Boolean> outgoingHttpRequestFilterMask,
            LinkedHashMap<Filter, Boolean> outgoingProxyResponseFilterMask) {
        this.incomingHttpResponseFilterSettings = incomingHttpResponseFilterMask;
        this.incomingProxyRequestFilterSettings = incomingProxyRequestFilterMask;
        this.outgoingHttpRequestFilterSettings = outgoingHttpRequestFilterMask;
        this.outgoingProxyResponseFilterSettings = outgoingProxyResponseFilterMask;
    }

    public boolean shouldProcess(BurpOperation operation, ToolType toolType) {
        LinkedHashMap<Filter, Boolean> filterSettings;
        int filterMask = 0;
        switch (operation) {
            case INCOMING_HTTP_RESPONSE:
                filterSettings = incomingHttpResponseFilterSettings;
                break;
            case INCOMING_PROXY_REQUEST:
                filterSettings = incomingProxyRequestFilterSettings;
                break;
            case OUTGOING_HTTP_REQUEST:
                filterSettings = outgoingHttpRequestFilterSettings;
                break;
            case OUTGOING_PROXY_RESPONSE:
                filterSettings = outgoingProxyResponseFilterSettings;
                break;
            default:
                filterSettings = new LinkedHashMap<>();
                break;
        }

        for (Map.Entry<Filter, Boolean> entry : filterSettings.entrySet()) {
            Filter filter = entry.getKey();
            if(filter.getToolType().equals(toolType)){
                return entry.getValue() == true;
            }
        }
        return false;
    }

    public LinkedHashMap<Filter,Boolean> getIncomingHttpResponseFilterSettings() {
        return this.incomingHttpResponseFilterSettings;
    }

    public void setIncomingHttpResponseFilterSettings(LinkedHashMap<Filter,Boolean> incomingHttpResponseFilterSettings) {
        this.incomingHttpResponseFilterSettings = incomingHttpResponseFilterSettings;
    }
    
    public LinkedHashMap<Filter,Boolean> getIncomingProxyRequestFilterSettings() {
        return this.incomingProxyRequestFilterSettings;
    }

    public void setIncomingProxyRequestFilterSettings(LinkedHashMap<Filter,Boolean> incomingProxyRequestFilterSettings) {
        this.incomingProxyRequestFilterSettings = incomingProxyRequestFilterSettings;
    }

    public LinkedHashMap<Filter,Boolean> getOutgoingHttpRequestFilterSettings() {
        return this.outgoingHttpRequestFilterSettings;
    }

    public void setOutgoingHttpRequestFilterSettings(LinkedHashMap<Filter,Boolean> outgoingHttpRequestFilterSettings) {
        this.outgoingHttpRequestFilterSettings = outgoingHttpRequestFilterSettings;
    }
    
    public LinkedHashMap<Filter,Boolean> getOutgoingProxyResponseFilterSettings() {
        return this.outgoingProxyResponseFilterSettings;
    }

    public void setOutgoingProxyResponseFilterSettings(LinkedHashMap<Filter,Boolean> outgoingProxyResponseFilterSettings) {
        this.outgoingProxyResponseFilterSettings = outgoingProxyResponseFilterSettings;
    }

    public String toString(){
        return "Incoming HTTP Response: " + this.incomingHttpResponseFilterSettings.toString()
                + "\nIncoming Proxy Request: " + this.incomingProxyRequestFilterSettings.toString()
                + "\nOutgoing HTTP Request: " + this.outgoingHttpRequestFilterSettings.toString()
                + "\nOutgoing Proxy Response: " + this.outgoingProxyResponseFilterSettings.toString();
    }

    public enum BurpOperation {
        INCOMING_HTTP_RESPONSE,
        INCOMING_PROXY_REQUEST,
        OUTGOING_HTTP_REQUEST,
        OUTGOING_PROXY_RESPONSE,
        FORMAT;

        public String toString(){
            switch(this){
                case INCOMING_HTTP_RESPONSE: return "Incoming_HTTP_Response";
                case INCOMING_PROXY_REQUEST: return "Incoming_Proxy_Request";
                case OUTGOING_HTTP_REQUEST: return "Outgoing_HTTP_Request";
                case OUTGOING_PROXY_RESPONSE: return "Outgoing_Proxy_Response";
                case FORMAT: return "Formatting";
                default: return "";
            }
        }
    }
}
