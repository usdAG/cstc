package de.usd.cstchef.operations.signature;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Enumeration;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.FormatTextField;

public abstract class SignatureOperation extends Operation implements ActionListener {

    protected String[] keyEntries = new String[] {};
    protected String[] keyStoreTypes = new String[] {"PKCS12", "JKS"};

    protected KeyStore keyStore = null;
    protected PrivateKeyEntry selectedEntry = null;

	protected File keyStoreFile = null;
	protected FormatTextField keyStorePass;

    protected JCheckBox keyStoreOpen;
    protected JButton chooseFileButton;
    protected JButton openKeyStoreButton;
	protected JComboBox<String> keyEntry;
	protected JComboBox<String> keyStoreType;
	protected JFileChooser fileChooser = new JFileChooser();


	public SignatureOperation() {
		super();
	}


	private void openKeyStore() {
        try {
          String storeType = (String)keyStoreType.getSelectedItem();
          String password = new String(keyStorePass.getText());
          KeyStore ks = KeyStore.getInstance(storeType);
          ks.load(new FileInputStream(keyStoreFile), password.toCharArray());
          this.keyStore = ks;
          this.keyStoreOpen.setSelected(true);
          this.updateKeyEntries();
        } catch( Exception e ) {
          this.resetKeyStore();
        }
	}


    private void updateKeyEntries() {
        try {
          Enumeration<String> entries = keyStore.aliases();
          keyEntry.removeAllItems();
          while (entries.hasMoreElements()) {
            keyEntry.addItem(entries.nextElement());
          }
        } catch( Exception e ) {
          this.resetKeyStore();
        }
    }


    private void selectKeyEntry() {
        try {
          String password = new String(keyStorePass.getText());
          String entryNumber = (String)keyEntry.getSelectedItem();
          selectedEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(entryNumber, new KeyStore.PasswordProtection(password.toCharArray()));
        } catch( Exception e ) {
          this.resetKeyStore();
        }
    }


    private void resetKeyStore() {
        this.keyStoreOpen.setSelected(false);
        keyStore = null;
        selectedEntry = null;
    }


	public void createMyUI() {
		this.keyStoreType = new JComboBox<>(this.keyStoreTypes);
		this.keyStoreType.addActionListener(this);
		this.addUIElement("KeyStoreType", this.keyStoreType);

		chooseFileButton = new JButton("Select file");
		chooseFileButton.addActionListener(this);
		this.addUIElement(null, this.chooseFileButton);

		this.keyStorePass = new FormatTextField();
		this.addUIElement("PrivKeyPassword", this.keyStorePass);

		openKeyStoreButton = new JButton("Open keystore");
		openKeyStoreButton.addActionListener(this);
		this.addUIElement(null, this.openKeyStoreButton);

		this.keyEntry = new JComboBox<>(keyEntries);
		this.keyEntry.addActionListener(this);
		this.addUIElement("KeyEntry", this.keyEntry);

        this.keyStoreOpen = new JCheckBox("KeyStore Opened");
        this.keyStoreOpen.setSelected(false);
		this.keyStoreOpen.addActionListener(this);
		this.addUIElement(null, this.keyStoreOpen);
	}

	@Override
	public void actionPerformed(ActionEvent arg0) {
        if( arg0.getSource() == keyStoreType ) {
          this.resetKeyStore();
        } else if( arg0.getSource() == openKeyStoreButton ) {
          this.resetKeyStore();
          this.openKeyStore();
        } else if( arg0.getSource() == chooseFileButton ) {
          this.resetKeyStore();
          int returnVal = fileChooser.showOpenDialog(this);
          if (returnVal == JFileChooser.APPROVE_OPTION) {
            keyStoreFile = fileChooser.getSelectedFile();
          }
        } else if( arg0.getSource() == keyEntry ) {
          this.selectKeyEntry();
        } 
        if( keyStore != null && keyEntry != null ) {
          this.notifyChange();
        }
	}
}
