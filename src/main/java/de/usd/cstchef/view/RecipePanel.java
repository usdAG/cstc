package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import burp.BurpUtils;
import burp.CstcMessageEditorController;
import burp.Logger;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import de.usd.cstchef.VariableStore;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;
import de.usd.cstchef.view.ui.PlaceholderTextField;
import de.usd.cstchef.view.ui.TextChangedListener;

public class RecipePanel extends JPanel implements ChangeListener {

    private int operationSteps = 10;
    private boolean autoBake = true;
    private MessageType messageType;
    private int bakeThreshold = 400;
    private String recipeName;
    private BurpOperation operation;

    private BurpEditorWrapper inputText;
    private BurpEditorWrapper outputText;

    private JPanel operationLines;

    private CstcMessageEditorController controllerOrig;
    private CstcMessageEditorController controllerMod;

    private Timer bakeTimer;

    private JLabel inactiveWarning;

    private static ImageIcon expandIcon = new ImageIcon(Operation.class.getResource("/expand_all.png"));
    private static ImageIcon collapseIcon = new ImageIcon(Operation.class.getResource("/collapse_all.png"));

    private static ImageIcon plusIcon = new ImageIcon(Operation.class.getResource("/plus.png"));
    private static ImageIcon minusIcon = new ImageIcon(Operation.class.getResource("/minus.png"));

    private JButton addLaneButton = new JButton();
    private JButton removeLaneButton = new JButton();

    private JCheckBox bakeCheckBox = new JCheckBox("Auto bake");
    private JButton bakeButton = new JButton("Bake");

    public RecipePanel(BurpOperation operation, MessageType messageType) {

        this.operation = operation;
        this.messageType = messageType;
        this.recipeName = operation.toString();

        ToolTipManager tooltipManager = ToolTipManager.sharedInstance();
        tooltipManager.setInitialDelay(0);
        this.setLayout(new GridLayout(0, 1));

        JSplitPane inOut = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        controllerOrig = new CstcMessageEditorController();
        controllerMod = new CstcMessageEditorController();

        // create input panel
        JPanel inputPanel = new LayoutPanel("Input");
        inputText = new BurpEditorWrapper(controllerOrig, messageType, this);
        inputPanel.add(inputText.uiComponent());

        /* 
         * This is necessary to have the distribution of space in all of the three RecipePanels uniform.
         * Request and Response Editor have different default sizes than the Raw Editor.
        */
        inputPanel.setPreferredSize(new Dimension(248, 0));
        inputPanel.setMinimumSize(new Dimension(248, 0));

        // create output panel
        JPanel outputPanel = new LayoutPanel("Output");
        outputText = new BurpEditorWrapper(controllerMod, messageType, this);
        outputPanel.add(outputText.uiComponent());

        outputPanel.setPreferredSize(new Dimension(248, 0));
        outputPanel.setMinimumSize(new Dimension(248, 0));

        JPanel searchTreePanel = new JPanel();
        searchTreePanel.setLayout(new BorderLayout());
        PlaceholderTextField searchText = new PlaceholderTextField("Search");
        searchTreePanel.add(searchText, BorderLayout.PAGE_START);

        OperationsTree operationsTree = new OperationsTree();
        operationsTree.setRootVisible(false);
        searchTreePanel.add(new JScrollPane(operationsTree));
        searchText.addTextChangedListener(new TextChangedListener() {

            @Override
            public void textChanged() {
                operationsTree.search(searchText.getText());
            }
            
        });
        JPanel btnContainer = new JPanel();
        JButton expandAll = new JButton();
        expandAll.setIcon(expandIcon);
        expandAll.setToolTipText("Expand all operations");
        expandAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                operationsTree.expandAll();
            }            
        });
        JButton collapseAll = new JButton();
        collapseAll.setIcon(collapseIcon);
        collapseAll.setToolTipText("Collapse all operations");
        collapseAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                operationsTree.collapseAll();
            }            
        });
        btnContainer.add(expandAll);
        btnContainer.add(collapseAll);
        searchTreePanel.add(btnContainer, BorderLayout.PAGE_END);

        // create operations panel
        JPanel operationsPanel = new LayoutPanel("Operations");
        operationsPanel.add(searchTreePanel);
        operationsPanel.setBackground(Color.WHITE);

        operationsPanel.setPreferredSize(new Dimension(100, 0));
        operationsPanel.setMinimumSize(new Dimension(100, 0));

        inOut.setTopComponent(inputPanel);
        inOut.setBottomComponent(outputPanel);
        inOut.setResizeWeight(0.5);

        // create active operations (middle) panel
        LayoutPanel activeOperationsPanel = new LayoutPanel("Recipe");

        inactiveWarning = new JLabel(this.operation.toString() + " Operations currently inactive!");
        inactiveWarning.setForeground(Color.RED);
        inactiveWarning.setFont(inactiveWarning.getFont().deriveFont(inactiveWarning.getFont().getStyle() | Font.BOLD));
        if(!this.operation.equals(BurpOperation.FORMAT))
            activeOperationsPanel.addActionComponent(inactiveWarning);

        // add action items
        JButton filters = new JButton("Filter");
        if(this.operation != BurpOperation.FORMAT)
            activeOperationsPanel.addActionComponent(filters);
        
        activeOperationsPanel.setPreferredSize(new Dimension(393, 0));
        activeOperationsPanel.setMinimumSize(new Dimension(393, 0));
        
        filters.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(null, RequestFilterDialog.getInstance(), "Request Filter",
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (result == JOptionPane.OK_OPTION) {
                    BurpUtils.getInstance().getFilterState().setFilterMask(
                            RequestFilterDialog.getInstance().getFilterMask(BurpOperation.INCOMING),
                            RequestFilterDialog.getInstance().getFilterMask(BurpOperation.OUTGOING));
                }
                BurpUtils.getInstance().getView().preventRaceConditionOnVariables();
                BurpUtils.getInstance().getView().updateInactiveWarnings();
                if (!BurpUtils.getInstance().getApi().burpSuite().version().edition()
                        .equals(BurpSuiteEdition.COMMUNITY_EDITION)) {
                    saveFilterState();
                }
            }
        });

        bakeButton.setEnabled(!autoBake);
        activeOperationsPanel.addActionComponent(bakeButton);
        bakeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                bake(false);
            }
        });

        JButton saveButton = new JButton("Save to File");
        activeOperationsPanel.addActionComponent(saveButton);
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                try {
                    JFileChooser fc = new JFileChooser();
                    int returnVal = fc.showSaveDialog(RecipePanel.this);
                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fc.getSelectedFile();
                        save(file);
                    }
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(null, "The file could not be saved.");
                }
            }
        });

        JButton loadButton = new JButton("Load");
        activeOperationsPanel.addActionComponent(loadButton);
        loadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                try {
                    JFileChooser fc = new JFileChooser();
                    int returnVal = fc.showOpenDialog(RecipePanel.this);
                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fc.getSelectedFile();
                        String jsonState = new String(Files.readAllBytes(Paths.get(file.getPath())));
                        restoreState(jsonState);
                    }
                } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | IOException e) {
                    JOptionPane.showMessageDialog(null, "The provided file could not be loaded.");
                }
            }
        });

        bakeCheckBox.setSelected(this.autoBake);
        activeOperationsPanel.addActionComponent(bakeCheckBox);
        bakeCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                autoBake = bakeCheckBox.isSelected();
                bakeButton.setEnabled(!autoBake);
                bake(false);
            }
        });

        JButton variablesButton = new JButton("Variables");
        activeOperationsPanel.addActionComponent(variablesButton);
        variablesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                VariablesWindow vw = VariablesWindow.getInstance();
                vw.refresh(VariableStore.getInstance().getVariables());
                vw.setVisible(true);
            }
        });

        JButton clearButton = new JButton("Clear");
        activeOperationsPanel.addActionComponent(clearButton);
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent arg0) {
                clear();
            }
        });

        operationLines = new JPanel();
        operationLines.setLayout(new GridBagLayout());

        // add dummy panel
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1;
        gbc.weighty = 1;
        JPanel dummyPanel = new JPanel();
        dummyPanel.setBackground(Color.YELLOW);

        GridBagConstraints co = new GridBagConstraints();
        co.gridheight = GridBagConstraints.REMAINDER;
        co.weighty = 1;
        co.fill = GridBagConstraints.VERTICAL;

        operationLines.add(dummyPanel, gbc); // this is the magic!11!!

        JScrollPane activeOperationsScrollPane = new JScrollPane(operationLines, JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        activeOperationsPanel.add(activeOperationsScrollPane);

        // button to add lanes
        addLaneButton.setIcon(plusIcon);

        GridBagConstraints btnConstrainsts = new GridBagConstraints();
        btnConstrainsts.gridheight = 1;
        btnConstrainsts.gridwidth = 1;
        btnConstrainsts.anchor = GridBagConstraints.NORTHEAST;
        
        operationLines.add(addLaneButton, btnConstrainsts, 0);
        addLaneButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if(operationSteps < 100) {
                    increaseLaneNumber(1);
                }

                // scroll max to the right if a lane is added. invokeLater because the maximum needs to be updated in the event queue first
                SwingUtilities.invokeLater(() -> activeOperationsScrollPane.getHorizontalScrollBar().setValue(activeOperationsScrollPane.getHorizontalScrollBar().getMaximum()));
            }
            
        });

        // button to remove lanes
        removeLaneButton.setIcon(minusIcon);
        operationLines.add(removeLaneButton, btnConstrainsts, 0);
        removeLaneButton.addActionListener(new ActionListener() {

            @Override
            public void actionPerformed(ActionEvent e) {
                if(operationSteps > 1) {
                    decreaseLaneNumber(1);
                }
            }
            
        });

        for (int i = operationSteps; i > 0; i--) {
            RecipeStepPanel opPanel = new RecipeStepPanel("Lane " + String.valueOf(i), this);
            operationLines.add(opPanel, co, 0);

            JPanel panel = opPanel.getOperationsPanel();
            MoveOperationMouseAdapter moma = new MoveOperationMouseAdapter(opPanel, operationLines);
            panel.addMouseListener(moma);
            panel.addMouseMotionListener(moma);
        }


        JSplitPane opsInOut = new JSplitPane();
        opsInOut.setResizeWeight(0.7);

        opsInOut.setLeftComponent(activeOperationsPanel);
        opsInOut.setRightComponent(inOut);

        JSplitPane opSplit = new JSplitPane();
        opSplit.setRightComponent(opsInOut);
        opSplit.setLeftComponent(operationsPanel);
        opSplit.setResizeWeight(0.1);

        this.add(opSplit);

        AddOperationMouseAdapter dma = new AddOperationMouseAdapter(operationsTree, operationLines);
        operationsTree.addMouseListener(dma);
        operationsTree.addMouseMotionListener(dma);

        startAutoBakeTimer();
    }

    public void disableAutobakeIfFilterActive() {
        for(Boolean b : BurpUtils.getInstance().getFilterState().getIncomingFilterSettings().values()) {
            if(b) {
                this.autoBake = false;
                this.bakeCheckBox.setSelected(false);
                this.bakeButton.setEnabled(true);
                this.bakeCheckBox.setEnabled(false);
                this.bakeCheckBox.setToolTipText("Auto bake is disabled if Filter is active.");
                return;
            }
            else if(!this.bakeCheckBox.isEnabled() && !b) {
                this.bakeCheckBox.setEnabled(true);
                this.bakeCheckBox.setToolTipText("");
            }
        }

        for(Boolean b : BurpUtils.getInstance().getFilterState().getOutgoingFilterSettings().values()) {
            if(b) {
                this.autoBake = false;
                this.bakeCheckBox.setSelected(false);
                this.bakeButton.setEnabled(true);
                this.bakeCheckBox.setEnabled(false);
                this.bakeCheckBox.setToolTipText("Auto bake is disabled if Filter is active.");
                return;
            }
            else if(!this.bakeCheckBox.isEnabled() && !b) {
                this.bakeCheckBox.setEnabled(true);
                this.bakeCheckBox.setToolTipText("");
            }
        }
    }   

    private void increaseLaneNumber(int number) {
        this.operationSteps += number;

        GridBagConstraints co = new GridBagConstraints();
        co.gridheight = GridBagConstraints.REMAINDER;
        co.weighty = 1;
        co.fill = GridBagConstraints.VERTICAL;

        for(int i = 0; i < number; i++) {
            RecipeStepPanel opPanel = new RecipeStepPanel("Lane " + String.valueOf(operationSteps - (number - i) + 1), this);
            operationLines.add(opPanel, co, operationSteps - (number - i));
            operationLines.revalidate();
            operationLines.repaint();

            JPanel panel = opPanel.getOperationsPanel();
            MoveOperationMouseAdapter moma = new MoveOperationMouseAdapter(opPanel, operationLines);
            panel.addMouseListener(moma);
            panel.addMouseMotionListener(moma);
        }
    }

    private void decreaseLaneNumber(int number) {
        int index = this.operationSteps;
        this.operationSteps -= number;
        for(int i = 0; i < number; i++) {
            operationLines.remove(index - 1 - i);
            operationLines.revalidate();
            operationLines.repaint();
        }
    }

    public void hideInactiveWarning(){
        this.inactiveWarning.setVisible(false);
    }

    public void showInactiveWarning(){
        this.inactiveWarning.setVisible(true);
    }

    public void setInput(HttpRequestResponse requestResponse) {
        if(messageType == MessageType.REQUEST){
            HttpRequest request = requestResponse.request();
            if(request == null)
                request = HttpRequest.httpRequest(ByteArray.byteArray("The message you have sent via the context menu is not a valid HTML request. Try using the formatting tab."));
            this.inputText.setRequest(request);
        }
        else if(messageType == MessageType.RESPONSE) {
            HttpResponse response = requestResponse.response();
            if(response == null)
                response = HttpResponse.httpResponse(ByteArray.byteArray("The message you have sent via the context menu does not have a valid HTML response. Try including a response to a request or use the formatting tab."));
            this.inputText.setResponse(response);
        }

        this.controllerOrig.setHttpRequestResponse(requestResponse);
        this.controllerMod.setHttpRequestResponse(requestResponse);

    }

    public void setFormatMessage(HttpRequestResponse requestResponse, MessageType messageType){
        ByteArray message;
        if(messageType == MessageType.REQUEST){
            message = requestResponse.request().toByteArray();
        }
        else{
            message = requestResponse.response().toByteArray();
        }
        if(message == null){
            message = ByteArray.byteArray("Message could not be parsed as a request or response.");
        }
        this.inputText.setContents(message);
        this.bake(false);
    }

    public void restoreState(String jsonState) throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        this.clear();
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(jsonState);
        JsonNode stepNodes;
        JsonNode versionNode;

        // check if "version" ObjectNode is there (since 1.3.2)
        if(rootNode.get(0) != null && rootNode.get(0).get("version") == null) {
            // recipes saved by CSTC <= 1.3.1
            stepNodes = rootNode;
        }
        else {
            // currently 1.3.2
            versionNode = rootNode.get(0);
            stepNodes = rootNode.get(1);
        }

        if (!stepNodes.isArray()) {
            throw new IOException("wrong data format");
        }

        if(stepNodes.size() > operationSteps) {
            increaseLaneNumber(stepNodes.size() - operationSteps);
        }

        for (int step = 0; step < stepNodes.size(); step++) {
            JsonNode operationNodes = stepNodes.get(step);
            if (!operationNodes.isArray()) {
                throw new IOException("wrong data format");
            }

            RecipeStepPanel panel = (RecipeStepPanel) this.operationLines.getComponent(step);

            /*  two types of ObjectNodes for every RecipeStepPanel:
                Lane information (always at index 0, if set) and the Operations

                If there's a lane ObjectNode we need to tell the inner loop to begin at index 1.
                The inner loop iterates over the Operations
            */
            int index = 0;
            if(operationNodes.get(0) != null) {
                if(operationNodes.get(0).get("lane_title") != null) {
                    index = 1;
                    panel.setTitle(operationNodes.get(0).get("lane_title").asText());
                }
                if(operationNodes.get(0).get("lane_comment") != null) {
                    index = 1;
                    panel.setComment(operationNodes.get(0).get("lane_comment").asText());
                }
            }

            for (int i = index; i < operationNodes.size(); i++) {
                JsonNode operationNode = operationNodes.get(i);
                String operation = operationNode.get("operation").asText();
                Map<String, Object> parameters =  mapper.convertValue(operationNode.get("parameters"), Map.class);
                Class<Operation> cls = (Class<Operation>) Class.forName(operation);

                // check if it is an operation
                Operation op = cls.newInstance();
                op.load(parameters);
                op.setDisabled(!operationNode.get("is_enabled").asBoolean());

                // check if "comment" attribute is set (since 1.3.2)
                if(operationNode.get("comment") != null) {
                    if(operationNode.get("comment").asText() != "null") {
                        op.setComment(operationNode.get("comment").asText());
                    }
                }
                // depending on if lane name is set we may start the loop at index 1, but want to add the first component at index 0
                panel.addComponent(op, index == 1 ? i-1 : i);
            }
        }
    }

    private String getStateAsJSON() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode rootNode = mapper.createArrayNode();
        ObjectNode versionNode = mapper.createObjectNode();
        ArrayNode stepsNode = mapper.createArrayNode();

        for (int step = 0; step < this.operationSteps; step++) {
            ArrayNode operationsNode = mapper.createArrayNode();

            RecipeStepPanel stepPanel = (RecipeStepPanel) this.operationLines.getComponent(step);

            // save lane name in case it differs from the default
            int laneNumber = step + 1;
            boolean laneNodeCreated = false;
            if(!stepPanel.getTitle().equals("Lane " + laneNumber)) {
                laneNodeCreated = true;
                ObjectNode laneNode = mapper.createObjectNode();
                laneNode.put("lane_title", stepPanel.getTitle());
                // save comment in same node in case it is set
                if(stepPanel.getComment() != null && !stepPanel.getComment().equals("")) {
                    laneNode.put("lane_comment", stepPanel.getComment());
                }
                operationsNode.add(laneNode);
            }

            // save comment in case it's not already
            if(!laneNodeCreated && stepPanel.getComment() != null && !stepPanel.getComment().equals("")) {
                ObjectNode laneNode = mapper.createObjectNode();
                laneNode.put("lane_comment", stepPanel.getComment());
                operationsNode.add(laneNode);
            }

            List<Operation> operations = stepPanel.getOperations();
            for (Operation op : operations) {
                ObjectNode operationNode = mapper.createObjectNode();
                operationNode.put("operation", op.getClass().getName());
                operationsNode.add(operationNode);
                operationNode.putPOJO("parameters", op.getState());
                operationNode.putPOJO("is_enabled", !op.isDisabled());
                // "comment":null if empty
                operationNode.put("comment", op.getComment());
            }
            stepsNode.add(operationsNode);
        }

        /*  maven performs a substitution at compile time in "/res/version.properties"
            with the version from pom.xml and here it reads from this file
        */
        Properties properties = new Properties();
        properties.load(RecipePanel.class.getResourceAsStream("/version.properties"));
        String version = properties.getProperty("version");

        versionNode.put("version", version);

        rootNode.add(versionNode);
        rootNode.add(stepsNode);

        return mapper.writeValueAsString(rootNode);
    }

    private void save(File file) throws IOException {
        FileWriter fw = new FileWriter(file);
        fw.write(getStateAsJSON());
        fw.close();
    }

    private ByteArray doBake(ByteArray input, MessageType messageType) {
        
        ByteArray result = input.copy();
        ByteArray intermediateResult = input;
        boolean outputChanged;
        VariableStore store = VariableStore.getInstance();
        out: for (int j = 0; j < this.operationLines.getComponentCount(); j++) {

            Component operationLine = this.operationLines.getComponent(j);
            if (!(operationLine instanceof RecipeStepPanel)) {
                continue;
            }

            String stepVariableName = String.format("%s_step%d", this.recipeName, (j + 1));
            store.removeVariable(stepVariableName);

            intermediateResult = input;
            outputChanged = false;

            List<Operation> operationList = ((RecipeStepPanel)operationLine).getOperations();
            for(int i = 0; i < operationList.size(); i++) {

                Operation op = operationList.get(i);
                if (op.isDisabled()) {
                    continue;
                }

                intermediateResult = op.performOperation(intermediateResult, messageType);
                outputChanged = true;

                if (op.isBreakpoint()) {
                    result = intermediateResult;
                    store.setVariable(stepVariableName, intermediateResult);
                    break out;
                }

                i += op.getOperationSkip();
                j += op.getLaneSkip();
            }

            if (outputChanged) {
                result = intermediateResult;
                store.setVariable(stepVariableName, intermediateResult);
            }
        }

        return result;
    }

    private void bake(boolean spamProtection) {
        if (this.bakeTimer != null) {
            this.bakeTimer.cancel();
        }
        this.bakeTimer = new Timer(this.recipeName);
        TimerTask tt = new TimerTask() {
            @Override
            public void run() {
                ByteArray result = doBake(inputText.getRequest() == null ? inputText.getContents() /* inputText.getResponse().toByteArray() */ : inputText.getRequest().toByteArray(), messageType);
                HashMap<String, ByteArray> variables = VariableStore.getInstance().getVariables();
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        if( messageType == MessageType.REQUEST) {
                            outputText.setRequest(HttpRequest.httpRequest(result));
                            controllerMod.setRequest(HttpRequest.httpRequest(result));
                        } else if (messageType == MessageType.RESPONSE){
                            outputText.setResponse(HttpResponse.httpResponse(result));
                            controllerMod.setResponse(HttpResponse.httpResponse(result));
                        }
                        else{
                            outputText.setContents(result);
                            // TODO: MessageEditorController?

                        }
                        VariablesWindow vw = VariablesWindow.getInstance();
                        if (vw.isVisible()) {
                            vw.refresh(variables);
                        }
                        PopupVariableMenu.refresh(variables);
                    }
                });
            }
        };
        int threshold = spamProtection ? this.bakeThreshold : 0;
        this.bakeTimer.schedule(tt, threshold);
    }

    public ByteArray bake(ByteArray input, MessageType messageType) {
        VariableStore store = VariableStore.getInstance();
        try {
            store.lock();
            return this.doBake(input, messageType);
        } finally {
            store.unlock();
        }
    }

    private void startAutoBakeTimer() {
        TimerTask repeatedTask = new TimerTask() {
            public void run() {
                if (inputText.isModified()) {
                    autoBake();
                }
            }
        };
        Timer timer = new Timer("Timer");
        long delay  = 1000L;
        long period = 1000L;
        timer.scheduleAtFixedRate(repeatedTask, delay, period);
    }

    public void autoBake() {
        if (!this.autoBake) {
            return;
        }
        VariableStore store = VariableStore.getInstance();
        try {
            store.lock();
            this.bake(true);
        } finally {
            store.unlock();
        }
    }

    private void saveRecipe() {
        PersistedObject savedState = BurpUtils.getInstance().getApi().persistence().extensionData();
        try {
            savedState.setString(this.operation + "Recipe", getStateAsJSON());
        } catch (IOException e) {
            Logger.getInstance().err(
                    "Could not save recipes to the Burp project. If you are running Burp Suite Community Edition, this behavior is expected since saving project files is exclusive to BurpSuite Pro users.");
        }
    }

    private void saveFilterState() {
        PersistedObject savedState = BurpUtils.getInstance().getApi().persistence().extensionData();
        try {
            savedState.setString("FilterState",
                    new ObjectMapper().writeValueAsString(BurpUtils.getInstance().getFilterState()));
        } catch (Exception e) {
            Logger.getInstance().err(
                    "Could not save the filter state to the Burp project. If you are running Burp Suite Community Edition, this behavior is expected since saving project files is exclusive to BurpSuite Pro users.\n"
                            + e.getMessage());
        }
    }

    private void clear() {
        if(this.operationSteps < 10) {
            increaseLaneNumber(10 - this.operationSteps);
        }
        else if(this.operationSteps > 10) {
            decreaseLaneNumber(this.operationSteps - 10);
        }
        
        for (int step = 0; step < this.operationSteps; step++) {
            RecipeStepPanel stepPanel = (RecipeStepPanel) this.operationLines.getComponent(step);
            int laneIndex = step + 1;
            stepPanel.setTitle("Lane " + laneIndex);
            stepPanel.clearComment();
            stepPanel.clearOperations();
        }
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        this.autoBake();

        if (!BurpUtils.getInstance().getApi().burpSuite().version().edition().equals(BurpSuiteEdition.COMMUNITY_EDITION)) {
            saveRecipe();
        }
    }

}
