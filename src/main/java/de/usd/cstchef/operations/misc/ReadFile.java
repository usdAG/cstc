package de.usd.cstchef.operations.misc;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.swing.JButton;
import javax.swing.JFileChooser;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Read File", category = OperationCategory.MISC, description = "Reads data from a file.")
public class ReadFile extends Operation implements ActionListener {

    // Max size set to 100MB per file
    private static final long MAX_FILE_SIZE_BYTES = 100L * 1024L * 1024L;

    private final JFileChooser fileChooser = new JFileChooser();
    private VariableTextField fileNameTxt;

    private VariableTextField basePathField;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        // canonicalize base directory (follows symlinks)
        Path basePath = Paths.get(basePathField.getText()).toRealPath();

        Path requestedPath = basePath.resolve(fileNameTxt.getText()).normalize();

        if(!Files.exists(requestedPath)){
            throw new IllegalArgumentException("The requested file does not exist.");
        }

        requestedPath = requestedPath.toRealPath();

        if(!requestedPath.startsWith(basePath)) {
            throw new IllegalArgumentException("The requested file is located outside the base directory.");
        }

        if (!Files.isRegularFile(requestedPath)) {
            throw new IllegalArgumentException("The requested path is not a regular file.");
        }        

        long fileSize = Files.size(requestedPath);
        if (fileSize > MAX_FILE_SIZE_BYTES) {
            throw new IllegalArgumentException("The requested file is too large. Maximum size is 100 MB.");
        }

        return factory.createByteArray(Files.readAllBytes(requestedPath));
    }

    public void createUI() {
        this.basePathField = new VariableTextField();
        this.addUIElement("Base path", this.basePathField);

        this.fileNameTxt = new VariableTextField();
        this.addUIElement("Filename", this.fileNameTxt);

        JButton chooseFileButton = new JButton("Select file");
        chooseFileButton.addActionListener(this);
        this.addUIElement(null, chooseFileButton, false, "button1");
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
