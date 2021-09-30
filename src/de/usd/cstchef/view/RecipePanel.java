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

import burp.BurpUtils;
import burp.CstcMessageEditorController;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.Logger;
import de.usd.cstchef.VariableStore;
import de.usd.cstchef.operations.Operation;

public class RecipePanel extends JPanel implements ChangeListener {

	private static Logger logger = Logger.getInstance();
	
	private int operationSteps = 10;
	private boolean autoBake = true;
	private boolean isRequest = true;
	private int bakeThreshold = 400;
	private String recipeName;
	private int filterMask;
	
	private BurpEditorWrapper inputText;
	private BurpEditorWrapper outputText;

	private JPanel operationLines;
	private RequestFilterDialog requestFilterDialog;

    private CstcMessageEditorController controllerOrig;
	private CstcMessageEditorController controllerMod;

	private Timer bakeTimer;
	
	public RecipePanel(String recipeName, boolean isRequest) {
		
		this.recipeName = recipeName;
        this.isRequest = isRequest;
		
		ToolTipManager tooltipManager = ToolTipManager.sharedInstance();
		tooltipManager.setInitialDelay(0);
		this.setLayout(new GridLayout(0, 1));

		JSplitPane inOut = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

		controllerOrig = new CstcMessageEditorController();
		controllerMod = new CstcMessageEditorController();

		// create input panel
		JPanel inputPanel = new LayoutPanel("Input");
		inputText = new BurpEditorWrapper(controllerOrig, true);
		inputPanel.add(inputText.getComponent());

		// create output panel
		JPanel outputPanel = new LayoutPanel("Output");
		outputText = new BurpEditorWrapper(controllerMod, false);
		outputPanel.add(outputText.getComponent());
		
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
		this.requestFilterDialog = new RequestFilterDialog();
		activeOperationsPanel.addActionComponent(filters);
		filters.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
		        int result = JOptionPane.showConfirmDialog(null, requestFilterDialog, "Request Filter", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		        if (result == JOptionPane.OK_OPTION) {
		        	filterMask = requestFilterDialog.getFilterMask();
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
		
		JButton saveButton = new JButton("Save");
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
		
		loadRecipeFromBurp();
		startAutoBakeTimer();
	}
	
	private void loadRecipeFromBurp() {
		logger.log("[" + this.recipeName + "] Autoloading...");
		boolean inBurp = BurpUtils.inBurp();
		//Check if we run inside a burp
		if (inBurp) {
			IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
			String jsonState = callbacks.loadExtensionSetting("cstc_" + this.recipeName);
			if (jsonState != null && jsonState != "") {
				try {
					logger.log("[" + this.recipeName + "] Restoring state.");
					//We remove the setting and set it again to be safe in an error case
					callbacks.saveExtensionSetting("cstc_" + this.recipeName, "");
					restoreState(jsonState);
					callbacks.saveExtensionSetting("cstc_" + this.recipeName, jsonState);
				} catch (ClassNotFoundException | InstantiationException | IllegalAccessException | IOException e) {					
					Logger.getInstance().err("There was an error restoring the state of RecipePanel " + this.recipeName);
				}
			}
		}
		else {
			logger.log("[" + this.recipeName + "] Autoloading aborted. Not running inside Burp.");
		}
	}
	
	private void autoSaveToBurp() {
		boolean inBurp = BurpUtils.inBurp();
		//Check if we run inside a burp
		if (inBurp) {
			try {
				String jsonState = getStateAsJSON();
				BurpUtils.getInstance().getCallbacks().saveExtensionSetting("cstc_" + this.recipeName, jsonState);				
			} catch (IOException e) {
				Logger.getInstance().err("There was an error persisting the current state of the recipe panel.");
			}
		}
	}
	
	public void setInput(IHttpRequestResponse requestResponse) {
        if( isRequest )
			this.inputText.setMessage(requestResponse.getRequest(), true);
		else {
			byte[] responseBytes = requestResponse.getResponse();
			if( responseBytes == null )
				responseBytes = "Your request has no server response yet :(".getBytes();
			this.inputText.setMessage(responseBytes, false);
		}

		this.controllerOrig.setHttpRequestResponse(requestResponse);
		this.controllerMod.setHttpRequestResponse(requestResponse);

		this.bake(false);
	}

	private void restoreState(String jsonState) throws IOException, ClassNotFoundException, InstantiationException, IllegalAccessException {
		// TODO do we want to remove all existing operations before loading here?
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
	
	private byte[] doBake(byte[] input) {
		if (input == null || input.length == 0) {
			return new byte[0];
		}
		byte[] result = input.clone();
		byte[] intermediateResult = input;
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
			IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
			IExtensionHelpers helpers = callbacks.getHelpers();

			IRequestInfo info;
            try {
                info = helpers.analyzeRequest(result);
            } catch( IllegalArgumentException e ) {
				// In this case there is no valid HTTP request and no Content-Length update is requried.
                return result;
            }

			List<java.lang.String> headers = info.getHeaders();
			int offset = info.getBodyOffset();
			
			if( result.length == offset ) {
				// In this case there is no body and we do not need to update the content length header.
				return result;
			}
			
			for(String header : headers) {
				if(header.startsWith("Content-Length:")) {
					// To update the content-length header, we just add a dummy parameter and remove it right away.
					// Burps extension helpers will care about updating the length without any string transformations.
					IParameter dummy = helpers.buildParameter("dummy", "dummy", IParameter.PARAM_BODY);
					result = helpers.addParameter(result, dummy);
					result = helpers.removeParameter(result, dummy);
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
				byte[] result = doBake(inputText.getMessage());
				HashMap<String, byte[]> variables = VariableStore.getInstance().getVariables();
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
                        if( isRequest) {
							outputText.setMessage(result, true);
							controllerMod.setRequest(result);
						} else {
							outputText.setMessage(result, false);
							controllerMod.setResponse(result);
						}
						VariablesWindow vw = VariablesWindow.getInstance();
						if (vw.isVisible()) {
							vw.refresh(variables);
						}
						PopupVariableMenu.refresh(variables);
					}
				});
				autoSaveToBurp();	
			}
		};
		int threshold = spamProtection ? this.bakeThreshold : 0;
		this.bakeTimer.schedule(tt, threshold);
	}
	
	public byte[] bake(byte[] input) {
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
	        	if (inputText.isMessageModified()) {
	        		logger.log("autobaking");
	        		autoBake();
	        	}
	        }
	    };
	    Timer timer = new Timer("Timer");	     
	    long delay  = 1000L;
	    long period = 1000L;
	    timer.scheduleAtFixedRate(repeatedTask, delay, period);
	}
	
	private void autoBake() {
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

	@Override
	public void stateChanged(ChangeEvent e) {
		this.autoBake();
	}

	public boolean shouldProcess(int tool) {
		return (this.filterMask & tool) != 0;
	}
}
