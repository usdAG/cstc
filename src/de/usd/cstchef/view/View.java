package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.security.Security;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class View extends JPanel {

	private RecipePanel incomingRecipePanel;
	private RecipePanel outgoingRecipePanel;
	private RecipePanel formatRecipePanel;

	public View() {
		Security.addProvider(new BouncyCastleProvider());
		
		this.setLayout(new BorderLayout());
		JTabbedPane tabbedPane = new JTabbedPane();

		incomingRecipePanel = new RecipePanel("Incomming", false);
		outgoingRecipePanel = new RecipePanel("Outgoing", true);
		formatRecipePanel = new RecipePanel("Formatting", true);

		tabbedPane.addTab("Outgoing Requests", null, outgoingRecipePanel, "Outgoing requests from the browser, the repeater or another tool.");
		tabbedPane.addTab("Incoming Responses", null, incomingRecipePanel, "Responses from the server.");
		tabbedPane.addTab("Formating", null, formatRecipePanel, "Formating for messages.");
		this.add(tabbedPane);
	}

	public RecipePanel getIncomingRecipePanel() {
		return this.incomingRecipePanel;
	}

	public RecipePanel getOutgoingRecipePanel() {
		return this.outgoingRecipePanel;
	}
	
	public RecipePanel getFormatRecipePanel() {
		return this.formatRecipePanel;
	}

	public static void main(String[] args) {
		JFrame frame = new JFrame("CSTC");
		frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		View view = new View();

		frame.setContentPane(view);
		frame.setSize(800, 600);
		frame.setVisible(true);
//		frame.setExtendedState(java.awt.Frame.MAXIMIZED_BOTH);
	}
}
