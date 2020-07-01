package de.usd.cstchef.operations.signature;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JPasswordField;

import de.usd.cstchef.operations.Operation;

public abstract class KeystoreOperation extends Operation implements ActionListener {

    protected String[] keyEntries = new String[] {};
    protected String[] keyStoreTypes = new String[] {"JKS", "PKCS12"};

    protected Certificate cert = null;
    protected KeyStore keyStore = null;
    protected PrivateKeyEntry selectedEntry = null;

	protected File keyStoreFile = null;
	protected JPasswordField keyStorePass;

    protected JCheckBox keyStoreOpen;
    protected JCheckBox certAvailable;
    protected JCheckBox keyAvailable;

    protected JButton chooseFileButton;
    protected JButton openKeyStoreButton;
	protected JComboBox<String> keyEntry;
	protected JComboBox<String> keyStoreType;
	protected JFileChooser fileChooser = new JFileChooser();

	public KeystoreOperation() {
		super();
	}

	private void openKeyStore() {
		try {
			
			String storeType = (String)keyStoreType.getSelectedItem();
			char[] password = keyStorePass.getPassword();
			KeyStore ks = KeyStore.getInstance(storeType);
			ks.load(new FileInputStream(keyStoreFile), password);
			this.keyStore = ks;
			this.keyStoreOpen.setSelected(true);
			this.certAvailable.setSelected(false);
			this.keyAvailable.setSelected(false);
			this.updateKeyEntries();
			
		} catch( Exception e ) {
	        this.resetKeyStore();
		}
	}

    private void updateKeyEntries(){
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

        String entry = (String)keyEntry.getSelectedItem();
        try {
            this.cert = keyStore.getCertificate(entry);
            if ( this.cert != null )
                this.certAvailable.setSelected(true);
            else
                this.certAvailable.setSelected(false);

        } catch( Exception e ) {
            this.certAvailable.setSelected(false);
        }

       char[] password = keyStorePass.getPassword();
       try {
		   this.selectedEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(entry, new KeyStore.PasswordProtection(password)); 
		   if ( this.selectedEntry != null )
	       	  this.keyAvailable.setSelected(true);
	       else
	       	  this.keyAvailable.setSelected(false);
       } catch( Exception e) {
	       this.keyAvailable.setSelected(false);
       }

    }


    private void resetKeyStore() {
        this.keyStoreOpen.setSelected(false);
		this.certAvailable.setSelected(false);
		this.keyAvailable.setSelected(false);
        keyStore = null;
        selectedEntry = null;
    }


	public void createMyUI() {
		this.keyStoreType = new JComboBox<>(this.keyStoreTypes);
		this.keyStoreType.addActionListener(this);
		this.addUIElement("KeyStoreType", this.keyStoreType);

		chooseFileButton = new JButton("Select file");
		chooseFileButton.addActionListener(this);
		this.addUIElement(null, this.chooseFileButton, "button1");

		this.keyStorePass = new JPasswordField();
		this.addUIElement("PrivKeyPassword", this.keyStorePass);

		openKeyStoreButton = new JButton("Open keystore");
		openKeyStoreButton.addActionListener(this);
		this.addUIElement(null, this.openKeyStoreButton, "button2");

		this.keyEntry = new JComboBox<>(keyEntries);
		this.keyEntry.addActionListener(this);
		this.addUIElement("KeyEntry", this.keyEntry);

        this.keyStoreOpen = new JCheckBox("KeyStore Opened");
        this.keyStoreOpen.setSelected(false);
        this.keyStoreOpen.setEnabled(false);
        this.keyStoreOpen.addActionListener(this);
		this.addUIElement(null, this.keyStoreOpen, "checkbox1");
		
		this.certAvailable = new JCheckBox("Certificate available");
        this.certAvailable.setSelected(false);
        this.certAvailable.setEnabled(false);
		this.certAvailable.addActionListener(this);
		this.addUIElement(null, this.certAvailable, "checkbox2");
		
		this.keyAvailable = new JCheckBox("PrivKey available");
        this.keyAvailable.setSelected(false);
        this.keyAvailable.setEnabled(false);
		this.keyAvailable.addActionListener(this);
		this.addUIElement(null, this.keyAvailable, "checkbox3");

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
