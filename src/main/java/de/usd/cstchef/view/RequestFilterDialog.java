package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import org.objectweb.asm.Label;

import burp.IBurpExtenderCallbacks;
import de.usd.cstchef.FilterState;
import de.usd.cstchef.FilterState.BurpOperation;

public class RequestFilterDialog extends JPanel {
    private LinkedHashMap<Filter, Boolean> incomingFilterSettings;
    private LinkedHashMap<Filter, Boolean> outgoingFilterSettings;
    private LinkedHashMap<Filter, Boolean> formatFilterSettings;

    public RequestFilterDialog() {
        this.setLayout(new GridLayout(0, 4));

        JPanel incomingPanel = createPanel(BurpOperation.INCOMING);
        JPanel outgoingPanel = createPanel(BurpOperation.OUTGOING);
        JPanel formatPanel = createPanel(BurpOperation.FORMAT);

        JPanel labelPanel = new JPanel();
        labelPanel.setLayout(new GridLayout(7, 0));
        labelPanel.add(new JLabel(""));
        List<String> labels = Arrays.asList("Proxy","Repeater","Spider","Scanner","Intruder","Extender");
        for(String label : labels){
            labelPanel.add(new JLabel(label));
        }

        this.add(labelPanel);
        this.add("Incoming", incomingPanel);
        this.add("Outgoing", outgoingPanel);
        this.add("Format", formatPanel);

    }

    private JPanel createPanel(BurpOperation operation) {
        LinkedHashMap<Filter, Boolean> filterSettings;
        
        filterSettings = new LinkedHashMap<>();
        filterSettings.put(new Filter("Proxy", IBurpExtenderCallbacks.TOOL_PROXY), false);
        filterSettings.put(new Filter("Repeater", IBurpExtenderCallbacks.TOOL_REPEATER), false);
        filterSettings.put(new Filter("Spider", IBurpExtenderCallbacks.TOOL_SPIDER), false);
        filterSettings.put(new Filter("Scanner", IBurpExtenderCallbacks.TOOL_SCANNER), false);
        filterSettings.put(new Filter("Intruder", IBurpExtenderCallbacks.TOOL_INTRUDER), false);
        filterSettings.put(new Filter("Extender", IBurpExtenderCallbacks.TOOL_EXTENDER), false);

        JPanel panel = new JPanel();
        panel.add(new JLabel(FilterState.translateBurpOperation(operation)));
        for (Map.Entry<Filter, Boolean> entry : filterSettings.entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();

            JCheckBox box = new JCheckBox();
            box.setSelected(selected);
            box.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    filterSettings.put(filter, box.isSelected());

                }
            });
            panel.add(box);
        }

        switch (operation) {
            case INCOMING:
                incomingFilterSettings = filterSettings;
            case OUTGOING:
                outgoingFilterSettings = filterSettings;
            case FORMAT:
                formatFilterSettings = filterSettings;
        }
        panel.setLayout(new GridLayout(7, 0));
        return panel;
    }

    public int getFilterMask(BurpOperation operation) {
        int filterMask = 0;
        LinkedHashMap<Filter, Boolean> filterSettings;
        switch (operation){
            case INCOMING: filterSettings = incomingFilterSettings;
            case OUTGOING: filterSettings = outgoingFilterSettings;
            case FORMAT: filterSettings = formatFilterSettings;
            default: filterSettings = new LinkedHashMap<>();
        }
        for (Map.Entry<Filter, Boolean> entry : filterSettings.entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();
            if (selected) {
                filterMask |= filter.getValue();
            }
        }
        return filterMask;
    }

    class Filter {
        private String name;
        private int value;

        public Filter(String name, int value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getValue() {
            return value;
        }

        public void setValue(int value) {
            this.value = value;
        }
    }
}
