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

    public RequestFilterDialog(FilterState filterState) {
        this.setLayout(new GridLayout(0, 4));

        incomingFilterSettings = filterState.getFilterMask(BurpOperation.INCOMING);
        outgoingFilterSettings = filterState.getFilterMask(BurpOperation.OUTGOING);
        formatFilterSettings = filterState.getFilterMask(BurpOperation.FORMAT);

        JPanel incomingPanel = createPanel(BurpOperation.INCOMING);
        JPanel outgoingPanel = createPanel(BurpOperation.OUTGOING);
        JPanel formatPanel = createPanel(BurpOperation.FORMAT);

        JPanel labelPanel = new JPanel();
        labelPanel.setLayout(new GridLayout(7, 0));
        labelPanel.add(new JLabel(""));
        List<String> labels = Arrays.asList("Proxy", "Repeater", "Spider", "Scanner", "Intruder", "Extender");
        for (String label : labels) {
            labelPanel.add(new JLabel(label));
        }

        this.add(labelPanel);
        this.add("Incoming", incomingPanel);
        this.add("Outgoing", outgoingPanel);
        this.add("Format", formatPanel);

    }

    private JPanel createPanel(BurpOperation operation) {
        LinkedHashMap<Filter, Boolean> filterSettings;

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
                filterSettings = new LinkedHashMap<Filter, Boolean>();
                break;
        }

        if (filterSettings.isEmpty()) {
            filterSettings.put(new Filter("Proxy", IBurpExtenderCallbacks.TOOL_PROXY), false);
            filterSettings.put(new Filter("Repeater", IBurpExtenderCallbacks.TOOL_REPEATER), false);
            filterSettings.put(new Filter("Spider", IBurpExtenderCallbacks.TOOL_SPIDER), false);
            filterSettings.put(new Filter("Scanner", IBurpExtenderCallbacks.TOOL_SCANNER), false);
            filterSettings.put(new Filter("Intruder", IBurpExtenderCallbacks.TOOL_INTRUDER), false);
            filterSettings.put(new Filter("Extender", IBurpExtenderCallbacks.TOOL_EXTENDER), false);
        }

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
                    LinkedHashMap<Filter, Boolean> filterSettings;

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
                            filterSettings = new LinkedHashMap<Filter, Boolean>();
                    }
                    filterSettings.put(filter, box.isSelected());
                }
            });
            panel.add(box);
        }

        panel.setLayout(new GridLayout(7, 0));
        return panel;
    }

    public LinkedHashMap<Filter, Boolean> getFilterMask(BurpOperation operation) {
        if (operation == BurpOperation.INCOMING) {
            return incomingFilterSettings;
        } else if (operation == BurpOperation.OUTGOING) {
            return outgoingFilterSettings;
        } else if (operation == BurpOperation.FORMAT) {
            return formatFilterSettings;
        } else {
            return new LinkedHashMap<>();
        }
    }

    public class Filter {
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
