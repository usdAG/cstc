package burp;

import java.awt.Component;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.plaf.basic.BasicTabbedPaneUI;
import javax.swing.text.JTextComponent;

import de.usd.cstchef.view.FormatTab;
import de.usd.cstchef.view.RecipePanel;
import de.usd.cstchef.view.View;

public class BurpExtender implements IBurpExtender, ITab, IMessageEditorTabFactory, IHttpListener, IContextMenuFactory {

	private final String extensionName = "CSTC";
	private IBurpExtenderCallbacks callbacks;
	private View view;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		Logger.getInstance().init(callbacks.getStdout(), callbacks.getStderr());
		BurpUtils.getInstance().init(callbacks);
		
		callbacks.setExtensionName(this.extensionName);
		callbacks.addSuiteTab(this);
		callbacks.registerHttpListener(this);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerMessageEditorTabFactory(this);
	}

	
	@Override
	public String getTabCaption() {
		return this.extensionName;
	}

	@Override
	public Component getUiComponent() {
		this.view = new View();
		return this.view;
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest && view.getOutgoingRecipePanel().shouldProcess(toolFlag)) {
			byte[] request = messageInfo.getRequest();
			byte[] modifiedRequest = view.getOutgoingRecipePanel().bake(request);
			Logger.getInstance().log("modified request: \n" + new String(modifiedRequest));
			messageInfo.setRequest(modifiedRequest);
		} else if (view.getIncomingRecipePanel().shouldProcess(toolFlag)) {
			byte[] response = messageInfo.getResponse();
			byte[] modifiedResponse = view.getIncomingRecipePanel().bake(response);
			messageInfo.setResponse(modifiedResponse);
			Logger.getInstance().log("modified response: \n" + new String(modifiedResponse));
		}
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invoc) {

		List<JMenuItem> menuItems = new ArrayList<>();
		JMenuItem incomingMenu = new JMenuItem("Send to CSTC (Incoming)");
		JMenuItem outgoingMenu = new JMenuItem("Send to CSTC (Outgoing)");
		JMenuItem incomingFormatMenu = new JMenuItem("Send to CSTC (Formating)");

		menuItems.add(incomingMenu);
		menuItems.add(outgoingMenu);
		menuItems.add(incomingFormatMenu);

		incomingMenu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] msgs = invoc.getSelectedMessages();
				if (msgs != null && msgs.length > 0) {
					view.getIncomingRecipePanel().setInput(new String(msgs[0].getResponse()));
				}
			}
		});

		outgoingMenu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] msgs = invoc.getSelectedMessages();
				if (msgs != null && msgs.length > 0) {
					view.getOutgoingRecipePanel().setInput(new String(msgs[0].getRequest()));
				}

			}
		});

		incomingFormatMenu.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] msgs = invoc.getSelectedMessages();
				if (msgs != null && msgs.length > 0) {
					view.getFormatRecipePanel().setInput(new String(msgs[0].getRequest()));
				}
			}
		});

		return menuItems;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		RecipePanel requestFormatPanel = this.view.getOutgoingRecipePanel();
		// TODO do we need the format panel or do we want to use the incoming recipe?
		RecipePanel responseFormatPanel = this.view.getFormatRecipePanel();
		return new FormatTab(requestFormatPanel, responseFormatPanel, editable);
	}
}