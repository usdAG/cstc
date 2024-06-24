package de.usd.cstchef.operations;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.EOFException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.Action;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.MatteBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import burp.BurpObjectFactory;
import burp.CstcObjectFactory;
import burp.Logger;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.ui.FormatTextField;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;

public abstract class Operation extends JPanel {

    private static Color defaultBgColor = new Color(223, 240, 216);
    private static Color defaultFontColor = new Color(70, 136, 71);
    private static Color disabledBgColor = new Color(223, 223, 223);
    private static Color disabledFontColor = new Color(153, 153, 153);
    private static Color breakBgColor = new Color(242, 222, 222);
    private static Color breakFontColor = new Color(185, 74, 72);
    private static Color errorBgColor = new Color(255, 121, 128);
    private static Color errorFontColor = new Color(185, 74, 72);

    private static ImageIcon breakIcon = new ImageIcon(Operation.class.getResource("/stop.png"));
    private static ImageIcon breakIconActive = new ImageIcon(Operation.class.getResource("/stop_active.png"));
    private static ImageIcon disableIcon = new ImageIcon(Operation.class.getResource("/disable.png"));
    private static ImageIcon removeIcon = new ImageIcon(Operation.class.getResource("/remove.png"));
    private static ImageIcon helpIcon = new ImageIcon(Operation.class.getResource("/help.png"));
    private static ImageIcon commentIcon = new ImageIcon(Operation.class.getResource("/comment.png"));
    private static ImageIcon noCommentIcon = new ImageIcon(Operation.class.getResource("/no-comment.png"));

    private NotifyChangeListener notifyChangeListener;

    private boolean breakpoint = false;
    private boolean disabled = false;
    private boolean error = false;

    private ChangeListener changeListener;
    private JTextArea errorArea;
    private Box contentBox;
    private Map<String, Component> uiElements;

    private String comment;
    private JButton commentButton;

    private int operationSkip = 0;
    private int laneSkip = 0;

    private final String httpRequestRegex = "(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)\\s/\\S*\\sHTTP/\\d(\\.\\d)?";
    private final String httpResponseRegex = "HTTP/\\d(\\.\\d)?\\s\\d{3}\\s(\\w*\\s?)*";

    public CstcObjectFactory factory;

    public Operation() {
        super();
        this.uiElements = new HashMap<>();
        this.factory = new BurpObjectFactory();

        this.setLayout(new BorderLayout());
        this.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));
        // set border
        Border margin = BorderFactory.createEmptyBorder(10, 10, 10, 10);
        MatteBorder lineBorder = new MatteBorder(0, 0, 1, 0, Color.BLACK);
        CompoundBorder border = new CompoundBorder(lineBorder, margin);
        this.setBorder(border);

        // add header
        JPanel header = new JPanel();
        header.setBackground(new Color(0, 0, 0, 0)); // transparent

        BoxLayout layout = new BoxLayout(header, BoxLayout.X_AXIS);
        header.setLayout(layout);
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        OperationInfos opInfos = this.getClass().getAnnotation(OperationInfos.class);

        JLabel titleLbl = new JLabel(opInfos.name());
        Font f = titleLbl.getFont();
        titleLbl.setFont(f.deriveFont(f.getStyle() | Font.BOLD));

        JButton disableBtn = createIconButton(Operation.disableIcon);
        disableBtn.setToolTipText("Disable");
        JButton breakpointBtn = createIconButton(Operation.breakIcon);
        breakpointBtn.setToolTipText("Breakpoint");
        JButton removeBtn = createIconButton(Operation.removeIcon);
        removeBtn.setToolTipText("Remove");
        JButton helpBtn = createIconButton(Operation.helpIcon);
        helpBtn.setToolTipText(opInfos.description());
        
        commentButton = createIconButton(noCommentIcon);
        commentButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                commentButton.setToolTipText(getComment());
                String comment = JOptionPane.showInputDialog("Edit comment:", commentButton.getToolTipText());
                commentButton.setToolTipText(comment);
                setComment(comment);
                ImageIcon newIcon = comment.isEmpty() ? Operation.noCommentIcon : Operation.commentIcon;
                commentButton.setIcon(newIcon);
            }
        });
        

        disableBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                disabled = !isDisabled();
                refreshColors();
                validate();
                repaint();
                notifyChange();
            }
        });

        breakpointBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                breakpoint = !isBreakpoint();
                ImageIcon newIcon = isBreakpoint() ? Operation.breakIconActive : Operation.breakIcon;
                breakpointBtn.setIcon(newIcon);
                refreshColors();
                validate();
                repaint();
                notifyChange();
            }
        });
        JPanel me = this;
        removeBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Container parent = getParent();
                onRemove();
                parent.remove(me);
                parent.validate();
                parent.repaint();
                notifyChange();
            }
        });

        header.add(titleLbl);
        header.add(Box.createHorizontalStrut(6));
        header.add(helpBtn);
        header.add(Box.createHorizontalStrut(3));
        header.add(commentButton);
        header.add(Box.createHorizontalGlue());
        header.add(disableBtn);
        header.add(Box.createHorizontalStrut(3));
        header.add(breakpointBtn);
        header.add(Box.createHorizontalStrut(3));
        header.add(removeBtn);

        this.add(header, BorderLayout.NORTH);

        errorArea = new JTextArea();
        errorArea.setEditable(false);
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setBackground(new Color(0, 0, 0, 0));
        errorArea.setFont(f.deriveFont(f.getStyle() | Font.BOLD));
        errorArea.setFocusable(false);
        errorArea.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));

        this.add(errorArea, BorderLayout.SOUTH);

        contentBox = Box.createVerticalBox();
        this.add(contentBox, BorderLayout.CENTER);

        this.createUI();
        this.refreshColors();
    }

    public String getComment() {
        return this.comment;
    }

    public void setComment(String comment) {
        if(comment != null) {
            this.comment = comment;
            commentButton.setIcon(Operation.commentIcon);
            commentButton.setToolTipText(comment);
        }
    }

    public Map<String, Object> getState() {
        Map<String, Object> properties = new HashMap<>();
        for (String key : this.uiElements.keySet()) {
            if (key.startsWith("noupdate"))
                properties.put(key, null);
            else
                properties.put(key, getUiValues(this.uiElements.get(key)));
        }

        return properties;
    }

    public <T> T checkNull(T input) throws Exception{
        if(input == null)
            throw new IllegalArgumentException("Parameter name not found.");
        return input;
    }

    private Object getUiValues(Component comp) {
        Object result = null;
        if (comp instanceof JPasswordField) {
            result = "";
        } else if (comp instanceof VariableTextArea) {
            result = ((VariableTextArea) comp).getRawText();
        } else if (comp instanceof VariableTextField) {
            result = ((VariableTextField) comp).getRawText();
        } else if (comp instanceof JTextField) {
            result = ((JTextField) comp).getText();
        } else if (comp instanceof JSpinner) {
            result = ((JSpinner) comp).getValue();
        } else if (comp instanceof JComboBox) {
            result = ((JComboBox<?>) comp).getSelectedItem();
            if (result != null)
                result = result.toString();
        } else if (comp instanceof JCheckBox) {
            result = ((JCheckBox) comp).isSelected();
        } else if (comp instanceof FormatTextField) {
            result = ((FormatTextField) comp).getValues();
        } else if (comp instanceof JFileChooser) {
            result = ((JFileChooser) comp).getName();
        }

        return result;
    }

    public void load(Map<String, Object> parameters) {
        for (String key : this.uiElements.keySet()) {
            Object value = parameters.get(key);
            this.setUiValue(this.uiElements.get(key), value);
        }
    }

    private void setUiValue(Component comp, Object value) {
        if (comp == null || value == null) {
            return;
        }

        if (comp instanceof JTextField) {
            ((JTextField) comp).setText((String) value);
        } else if (comp instanceof JSpinner) {
            ((JSpinner) comp).setValue(value);
        } else if (comp instanceof JComboBox) {
            ((JComboBox<?>) comp).setSelectedItem(value);
        } else if (comp instanceof VariableTextArea) {
            ((VariableTextArea) comp).setText((String) value);
        } else if (comp instanceof JCheckBox) {
            ((JCheckBox) comp).setSelected((boolean) value);
        } else if (comp instanceof FormatTextField) {
            ((FormatTextField) comp).setValues((Map<String, String>) value);
        } else if (comp instanceof JFileChooser) {
            ((JFileChooser) comp).setName((String) value);
        }
    }

    private JButton createIconButton(ImageIcon icon) {
        JButton btn = new JButton();
        btn.setBorder(BorderFactory.createEmptyBorder());
        btn.setIcon(icon);
        btn.setContentAreaFilled(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setAlignmentX(Component.RIGHT_ALIGNMENT);

        return btn;
    }

    private void refreshColors() {
        Color bgColor;
        Color fontColor;
        if (this.isDisabled()) {
            bgColor = Operation.disabledBgColor;
            fontColor = Operation.disabledFontColor;
        } else if (this.isError()) {
            bgColor = Operation.errorBgColor;
            fontColor = Operation.errorFontColor;
        } else if (this.isBreakpoint()) {
            bgColor = Operation.breakBgColor;
            fontColor = Operation.breakFontColor;
        } else {
            bgColor = Operation.defaultBgColor;
            fontColor = Operation.defaultFontColor;
        }

        this.setBackground(bgColor);
        this.changeFontColor(this, fontColor);
    }

    private void changeFontColor(Container container, Color color) {
        for (Component comp : container.getComponents()) {
            if (comp instanceof JLabel || comp.equals(errorArea)) {
                comp.setForeground(color);
            } else if (comp instanceof Container) {
                changeFontColor((Container) comp, color);
            }
        }
    }

    protected void addUIElement(String caption, Component comp) {
        this.addUIElement(caption, comp, true, null);
    }

    protected void addUIElement(String caption, Component comp, boolean notifyChange) {
        this.addUIElement(caption, comp, notifyChange, null);
    }

    protected void addUIElement(String caption, Component comp, String identifier) {
        this.addUIElement(caption, comp, true, identifier);
    }

    protected void addUIElement(String caption, Component comp, boolean notifyChange, String identifier) {
        comp.setCursor(Cursor.getDefaultCursor());

        Box box = Box.createHorizontalBox();
        box.setAlignmentX(Component.LEFT_ALIGNMENT);
        if (comp instanceof JCheckBox) {
            comp.setBackground(new Color(0, 0, 0, 0));
        }
        JLabel lbl = new JLabel(caption);
        box.add(lbl);
        box.add(Box.createHorizontalStrut(10));
        box.add(comp);
        this.contentBox.add(box);
        this.contentBox.add(Box.createVerticalStrut(10));
        if (identifier == null)
            identifier = caption;
        this.uiElements.put(identifier, comp);

        if (notifyChange) {
            if (notifyChangeListener == null) {
                notifyChangeListener = new NotifyChangeListener();
            }

            if (comp instanceof JTextField) {
                ((JTextField) comp).getDocument().addDocumentListener(notifyChangeListener);
            } else if (comp instanceof JSpinner) {
                ((JSpinner) comp).addChangeListener(notifyChangeListener);
            } else if (comp instanceof JComboBox) {
                ((JComboBox<?>) comp).addActionListener(notifyChangeListener);
            } else if (comp instanceof VariableTextArea) {
                ((VariableTextArea) comp).addDocumentListener(notifyChangeListener);
            } else if (comp instanceof JCheckBox) {
                ((JCheckBox) comp).addActionListener(notifyChangeListener);
            } else if (comp instanceof FormatTextField) {
                ((FormatTextField) comp).addDocumentListener(notifyChangeListener);
            } else {
                Logger.getInstance().err("could not add a default change listener for " + comp.getClass());
            }
        }
        refreshColors();
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension dim = super.getPreferredSize();
        int width = this.getParent().getWidth();
        dim.setSize(width, dim.height);
        return dim;
    }

    public ByteArray performOperation(ByteArray input, MessageType messageType) {
        try {
            ByteArray result = this.perform(input, messageType);
            this.setErrorMessage(null);
            return result;
        } catch (EOFException e) {
            this.setErrorMessage(new EOFException("End of file"));
            return factory.createByteArray(0);
        } catch (Throwable e) {
            this.setErrorMessage(e);
            return factory.createByteArray(0);
        }
    }

    public void setErrorMessage(Throwable e) {
        boolean error = e != null;

        String msg = error ? e.getMessage() : "";
        String text;
        if (msg == null) {
            text = e.getClass().getName();
        } else {
            text = error ? (msg.isEmpty() ? e.toString() : msg) : "";
        }

        this.errorArea.setText(text);

        this.setError(error);
        this.refreshColors();
        this.validate();
        this.repaint();
    }

    public void removeChangeListener() {
        this.changeListener = null;
    }

    public void setChangeListener(ChangeListener listener) {
        this.changeListener = listener;
    }

    protected void notifyChange() {
        if (this.changeListener != null) {
            this.changeListener.stateChanged(new ChangeEvent(this));
        }
    }

    public boolean isBreakpoint() {
        return breakpoint;
    }

    public void setBreakpoint(boolean breakpoint) {
        this.breakpoint = breakpoint;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
        refreshColors();
        validate();
        repaint();
        notifyChange();
    }

    public boolean isError() {
        return error;
    }

    public void setError(boolean error) {
        this.error = error;
    }

    public void setOperationSkip(int count) {
        if (count < 0)
            count = 0;
        this.operationSkip = count;
    }

    public int getOperationSkip() {
        return this.operationSkip;
    }

    public void setLaneSkip(int count) {
        if (count < 0)
            count = 0;
        this.laneSkip = count;
    }

    public int getLaneSkip() {
        return this.laneSkip;
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    public @interface OperationInfos {

        public String name()

        default "Unnamed plugin!";

        public String description()

        default "Change this description!";

        public OperationCategory category() default OperationCategory.MISC;
    }

    protected abstract ByteArray perform(ByteArray input, MessageType messageType) throws Exception;

    public void createUI() {

    }

    public void onRemove() {

    }
    
    public MessageType parseMessageType(ByteArray input) throws Exception{
        final Pattern requestPattern = Pattern.compile(httpRequestRegex);
        final Matcher requestMatcher = requestPattern.matcher(input.toString().split("\n")[0].trim());
        if (requestMatcher.matches()) {
            return MessageType.REQUEST;
        }

        final Pattern responsePattern = Pattern.compile(httpResponseRegex);
        final Matcher responseMatcher = responsePattern.matcher(input.toString().split("\n")[0].trim());
        if (responseMatcher.matches()) {
            return MessageType.RESPONSE;
        }

        throw new IllegalArgumentException("Input is not a valid HTTP message");
    }

    public ByteArray parseRawMessage(ByteArray input) throws Exception{
        return perform(input, parseMessageType(input));
    }

    private class NotifyChangeListener implements DocumentListener, ActionListener, ChangeListener {

        @Override
        public void changedUpdate(DocumentEvent e) {
            notifyChange();
        }

        @Override
        public void insertUpdate(DocumentEvent e) {
            notifyChange();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            notifyChange();
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            notifyChange();
        }

        @Override
        public void stateChanged(ChangeEvent e) {
            notifyChange();
        }
    }
}
