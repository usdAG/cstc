package de.usd.cstchef.view;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import burp.BurpUtils;
import burp.api.montoya.core.ToolType;
import de.usd.cstchef.view.filter.Filter;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

public class RequestFilterDialog extends JPanel {

    private static RequestFilterDialog instance = null;

    public static RequestFilterDialog getInstance() {
        if (RequestFilterDialog.instance == null) {
            RequestFilterDialog.instance = new RequestFilterDialog();
        }
        return RequestFilterDialog.instance;
    }

    private RequestFilterDialog() {
        this.setLayout(new GridLayout(0, 3));

        JPanel incomingHttpResponsePanel = createHttpPanel(BurpOperation.INCOMING_HTTP_RESPONSE);
        JPanel incomingProxyRequestPanel = createProxyPanel(BurpOperation.INCOMING_PROXY_REQUEST);
        JPanel outgoingHttpRequestPanel = createHttpPanel(BurpOperation.OUTGOING_HTTP_REQUEST);
        JPanel outgoingProxyResponsePanel = createProxyPanel(BurpOperation.OUTGOING_PROXY_RESPONSE);

        JPanel labelPanel = new JPanel();
        labelPanel.setLayout(new GridLayout(7, 0));
        labelPanel.add(new JLabel(""));
        List<String> labels = Arrays.asList("Proxy", "Repeater", "Scanner", "Intruder", "Extender", "Sequencer");
        for (String label : labels) {
            labelPanel.add(new JLabel(label));
        }

        this.removeAll();
        this.add(labelPanel);
        this.add("Outgoing HTTP Request", outgoingHttpRequestPanel);
        this.add("Incoming HTTP Response", incomingHttpResponsePanel);
        this.add("Incoming Proxy Request", incomingProxyRequestPanel);
        this.add("Outgoing Proxy Response", outgoingProxyResponsePanel);

    }

    private JPanel createHttpPanel(BurpOperation operation) {
        if (BurpUtils.getInstance().getFilterState().getFilterMask(operation).isEmpty()) {
            BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(new Filter(ToolType.PROXY, ToolType.PROXY.ordinal()), false);
            BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(new Filter(ToolType.REPEATER, ToolType.REPEATER.ordinal()), false);
            BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(new Filter(ToolType.SCANNER, ToolType.SCANNER.ordinal()), false);
            BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(new Filter(ToolType.INTRUDER, ToolType.INTRUDER.ordinal()), false);
            BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(new Filter(ToolType.EXTENSIONS, ToolType.EXTENSIONS.ordinal()), false);
            BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(new Filter(ToolType.SEQUENCER, ToolType.SEQUENCER.ordinal()), false);
        }

        JPanel panel = new JPanel();
        panel.add(new JLabel(operation.toString()));
        for (Map.Entry<Filter, Boolean> entry : BurpUtils.getInstance().getFilterState().getFilterMask(operation).entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();

            JCheckBox box = new JCheckBox();
            box.setSelected(selected);
            box.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(filter, box.isSelected());
                }
            });
            panel.add(box);
        }

        panel.setLayout(new GridLayout(7, 0));
        return panel;
    }
    
    private JPanel createProxyPanel(BurpOperation operation) {
        if (BurpUtils.getInstance().getFilterState().getFilterMask(operation).isEmpty()) {
            BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(new Filter(ToolType.PROXY, ToolType.PROXY.ordinal()), false);
        }
        JPanel panel = new JPanel();
        for (Map.Entry<Filter, Boolean> entry : BurpUtils.getInstance().getFilterState().getFilterMask(operation).entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();

            JCheckBox box = new JCheckBox();
            box.setSelected(selected);
            box.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    BurpUtils.getInstance().getFilterState().getFilterMask(operation).put(filter, box.isSelected());
                }
            });
            panel.add(box);
        }
        panel.add(new JLabel(operation.toString()));
        return panel;
    }

    public void updateFilterSettings(){
        RequestFilterDialog.instance = new RequestFilterDialog();
    }

    public LinkedHashMap<Filter, Boolean> getFilterMask(BurpOperation operation) {
        return BurpUtils.getInstance().getFilterState().getFilterMask(operation);
    }
}
