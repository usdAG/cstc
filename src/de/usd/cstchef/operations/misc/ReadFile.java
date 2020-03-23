package de.usd.cstchef.operations.misc;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Read File", category = OperationCategory.MISC, description = "Reads data from a file.")
public class ReadFile extends Operation implements ActionListener {

	private final JFileChooser fileChooser = new JFileChooser();
	private VariableTextField fileNameTxt;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		String path = fileNameTxt.getText();
		
		File file = new File(path);
		FileInputStream fis = new FileInputStream(file);
		byte[] data = new byte[(int) file.length()];
		fis.read(data);
		fis.close();
		
		return data;
	}

	public void createUI() {
		this.fileNameTxt = new VariableTextField();
		this.addUIElement("Filename", this.fileNameTxt);

		JButton chooseFileButton = new JButton("Select file");
		chooseFileButton.addActionListener(this);
		this.addUIElement(null, chooseFileButton);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		int returnVal = fileChooser.showOpenDialog(this);
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			File file = fileChooser.getSelectedFile();
			this.fileNameTxt.setText(file.getAbsolutePath());
		}
	}

}
