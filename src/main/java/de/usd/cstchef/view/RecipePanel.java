package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
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
import java.util.Timer;
import java.util.TimerTask;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.CstcMessageEditorController;
import burp.Logger;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import de.usd.cstchef.FilterState;
import de.usd.cstchef.Utils;
import de.usd.cstchef.VariableStore;
import de.usd.cstchef.FilterState.BurpOperation;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;

public class RecipePanel extends JPanel implements ChangeListener {

    private static Logger logger = Logger.getInstance();

    private int operationSteps = 10;
    private boolean autoBake = true;
    private MessageType messageType;
    private int bakeThreshold = 400;
    private String recipeName;
    private BurpOperation operation;

    private BurpEditorWrapper inputText;
    private BurpEditorWrapper outputText;

    private JPanel operationLines;
    private RequestFilterDialog requestFilterDialog;

    private CstcMessageEditorController controllerOrig;
    private CstcMessageEditorController controllerMod;

    private Timer bakeTimer;

    private FilterState filterState;

    public RecipePanel(BurpOperation operation, MessageType messageType, FilterState filterState) {

        this.operation = operation;
        this.messageType = messageType;
        this.filterState = filterState;
        this.recipeName = FilterState.translateBurpOperation(operation);

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

        // create output panel
        JPanel outputPanel = new LayoutPanel("Output");
        outputText = new BurpEditorWrapper(controllerMod, messageType, this);
        outputPanel.add(outputText.uiComponent());

        JPanel searchTreePanel = new JPanel();
        searchTreePanel.setLayout(new BorderLayout());
        JTextField searchText = new JTextField();
        searchTreePanel.add(searchText, BorderLayout.PAGE_START);

        OperationsTree operationsTree = new OperationsTree();
        operationsTree.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        operationsTree.setRootVisible(false);
        searchTreePanel.add(new JScrollPane(operationsTree));
        searchText.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void removeUpdate(DocumentEvent e) {
                operationsTree.search(searchText.getText());
            }

            @Override
            public void insertUpdate(DocumentEvent e) {
                operationsTree.search(searchText.getText());
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                operationsTree.search(searchText.getText());
            }
        });

        // create operations panel
        JPanel operationsPanel = new LayoutPanel("Operations");
        operationsPanel.add(searchTreePanel);
        operationsPanel.setBackground(Color.WHITE);
        inOut.setTopComponent(inputPanel);
        inOut.setBottomComponent(outputPanel);
        inOut.setResizeWeight(0.5);

        // create active operations (middle) panel
        LayoutPanel activeOperationsPanel = new LayoutPanel("Recipe");

        // add action items
        JButton filters = new JButton("Filter");
        this.requestFilterDialog = RequestFilterDialog.getInstance();
        activeOperationsPanel.addActionComponent(filters);
        filters.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(null, requestFilterDialog, "Request Filter",
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (result == JOptionPane.OK_OPTION) {
                    filterState.setFilterMask(requestFilterDialog.getFilterMask(BurpOperation.INCOMING),
                            requestFilterDialog.getFilterMask(BurpOperation.OUTGOING),
                            requestFilterDialog.getFilterMask(BurpOperation.FORMAT));
                }
            }
        });

        JButton bakeButton = new JButton("Bake");
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

        JCheckBox bakeCheckBox = new JCheckBox("Auto bake");
        bakeCheckBox.setSelected(this.autoBake);
        activeOperationsPanel.addActionComponent(bakeCheckBox);
        bakeCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                autoBake = bakeCheckBox.isSelected();
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

        for (int i = operationSteps; i > 0; i--) {
            RecipeStepPanel opPanel = new RecipeStepPanel(String.valueOf(i), this);
            operationLines.add(opPanel, co, 0);

            JPanel panel = opPanel.getOperationsPanel();
            MoveOperationMouseAdapter moma = new MoveOperationMouseAdapter(opPanel, operationLines);
            panel.addMouseListener(moma );
            panel.addMouseMotionListener(moma );
        }

        JScrollPane activeOperationsScrollPane = new JScrollPane(operationLines, JScrollPane.VERTICAL_SCROLLBAR_NEVER,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        activeOperationsPanel.add(activeOperationsScrollPane);

        JSplitPane opsInOut = new JSplitPane();
        opsInOut.setResizeWeight(0.5);

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
        startAutoSaveTimer();
    }

    public FilterState getFilterState() {
        return filterState;
    }

    public void setFilterState(FilterState state){
        this.filterState = state;
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

        this.bake(false);
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
        // TODO do we want to remove all existing operations before loading here?
        this.clear(); // Yes!
        ObjectMapper mapper = new ObjectMapper();
        JsonNode stepNodes = mapper.readTree(jsonState);
        if (!stepNodes.isArray()) {
            throw new IOException("wrong data format");
        }

        for (int step = 0; step < stepNodes.size(); step++) {
            JsonNode operationNodes = stepNodes.get(step);
            if (!operationNodes.isArray()) {
                throw new IOException("wrong data format");
            }

            for (int i = 0; i < operationNodes.size(); i++) {
                JsonNode operationNode = operationNodes.get(i);
                String operation = operationNode.get("operation").asText();
                Map<String, Object> parameters =  mapper.convertValue(operationNode.get("parameters"), Map.class);
                Class<Operation> cls = (Class<Operation>) Class.forName(operation);
                // check if it is an operation
                Operation op = cls.newInstance();
                op.load(parameters);
                op.setDisabled(!operationNode.get("is_enabled").asBoolean());
                RecipeStepPanel panel = (RecipeStepPanel) this.operationLines.getComponent(step);
                panel.addComponent(op, i);
            }
        }
    }

    private String getStateAsJSON() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        ArrayNode stepsNode = mapper.createArrayNode();

        for (int step = 0; step < this.operationSteps; step++) {
            ArrayNode operationsNode = mapper.createArrayNode();

            RecipeStepPanel stepPanel = (RecipeStepPanel) this.operationLines.getComponent(step);
            List<Operation> operations = stepPanel.getOperations();
            for (Operation op : operations) {
                ObjectNode operationNode = mapper.createObjectNode();
                operationNode.put("operation", op.getClass().getName());
                operationsNode.add(operationNode);
                operationNode.putPOJO("parameters", op.getState());
                operationNode.putPOJO("is_enabled", !op.isDisabled());
            }
            stepsNode.add(operationsNode);
        }
        return mapper.writeValueAsString(stepsNode);
    }

    private void save(File file) throws IOException {
        FileWriter fw = new FileWriter(file);
        fw.write(getStateAsJSON());
        fw.close();
    }

    private ByteArray doBake(ByteArray input) {
        if (input == null || input.length() == 0) {
            return ByteArray.byteArrayOfLength(0);
        }
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

                intermediateResult = op.performOperation(intermediateResult);
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

        if (BurpUtils.inBurp()) {
            MontoyaApi api = BurpUtils.getInstance().getApi();
            HttpRequest req;
            try {
                req = HttpRequest.httpRequest(result);

            } catch( IllegalArgumentException e ) {
                // In this case there is no valid HTTP request and no Content-Length update is requried.
                return result;
            }

            List<HttpHeader> headers = req.headers();
            int offset = req.bodyOffset();

            if( result.length() == offset ) {
                // In this case there is no body and we do not need to update the content length header.
                return result;
            }

            

            for(HttpHeader header : headers) {
                if(header.toString().startsWith("Content-Length:")) {
                    HttpParameter dummy = HttpParameter.bodyParameter("dummy", "dummy");
                    result = HttpRequest.httpRequest(result).withAddedParameters(dummy).withRemovedParameters(dummy).toByteArray();
                    break;
                }
            }
            return result;

        } else {
            return result;
        }
    }

    private void bake(boolean spamProtection) {
        if (this.bakeTimer != null) {
            this.bakeTimer.cancel();
        }
        this.bakeTimer = new Timer(this.recipeName);
        TimerTask tt = new TimerTask() {
            @Override
            public void run() {
                ByteArray result = doBake(inputText.getRequest() == null ? inputText.getContents() /* inputText.getResponse().toByteArray() */ : inputText.getRequest().toByteArray());
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

    public ByteArray bake(ByteArray input) {
        VariableStore store = VariableStore.getInstance();
        try {
            store.lock();
            return this.doBake(input);
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

    private void startAutoSaveTimer() {
        TimerTask autoSaveTask = new TimerTask() {
            public void run() {
                autoSave();
            }
        };
        Timer timer = new Timer("Timer");
        long delay  = 10000L;
        long period = 10000L;
        timer.scheduleAtFixedRate(autoSaveTask, delay, period);
    }

    public void autoSave(){
        PersistedObject savedState = BurpUtils.getInstance().getApi().persistence().extensionData();
        try {
            savedState.setString(this.operation + "Recipe", getStateAsJSON());
        } catch (IOException e) {
            Logger.getInstance().err("Could not save recipes to the Burp project. If you are running Burp Suite Community Edition, this behavior is expected since saving project files is exclusive to BurpSuite Pro users.");
        }
        try{
            savedState.setString("FilterState", new ObjectMapper().writeValueAsString(filterState));
        }
        catch(Exception e){
            Logger.getInstance().err("Could not save the filter state to the Burp project. If you are running Burp Suite Community Edition, this behavior is expected since saving project files is exclusive to BurpSuite Pro users.\n" + e.getMessage());
        }
    }

    private void clear() {
        for (int step = 0; step < this.operationSteps; step++) {
            RecipeStepPanel stepPanel = (RecipeStepPanel) this.operationLines.getComponent(step);
            stepPanel.clearOperations();
        }
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        this.autoBake();
    }

}
