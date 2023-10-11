package de.usd.cstchef.view;

import java.awt.Component;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Optional;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import burp.BurpUtils;
import burp.CstcMessageEditorController;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.Editor;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.RawEditor;
import de.usd.cstchef.Utils.MessageType;

public class BurpEditorWrapper implements HttpRequestEditor, HttpResponseEditor, RawEditor, DocumentListener{

    private boolean isModified;
    private boolean editable;
    private MessageType messageType;
    private MontoyaApi api;
    private boolean fallbackMode;
    private JTextArea fallbackArea;
    private Editor burpEditor;
    private ByteArray lastContent;
    private RecipePanel recipePanel;

    public BurpEditorWrapper(CstcMessageEditorController controller, MessageType messageType, RecipePanel panel){
        this.api = BurpUtils.getInstance().getApi();
        this.messageType = messageType;
        this.recipePanel = panel;
        if (BurpUtils.inBurp()) {
            switch(messageType){
                case REQUEST: burpEditor = api.userInterface().createHttpRequestEditor(); break;
                case RESPONSE: burpEditor = api.userInterface().createHttpResponseEditor(); break;
                case RAW: burpEditor = api.userInterface().createRawEditor(); break;
                default: break;
            }
            fallbackMode = false;
        } else {
            this.fallbackArea = new JTextArea();
            this.fallbackArea.getDocument().addDocumentListener(this);
            this.burpEditor.uiComponent().addHierarchyListener(null);
            fallbackMode = true;
        }
    }


    @Override
    public void changedUpdate(DocumentEvent arg0) {
        this.isModified = true;
        recipePanel.autoBake();
    }

    @Override
    public void insertUpdate(DocumentEvent arg0) {
        this.isModified = true;
        recipePanel.autoBake();
    }

    @Override
    public void removeUpdate(DocumentEvent arg0) {
        this.isModified = true;
        recipePanel.autoBake();
    }

    @Override
    public void setEditable(boolean editable) {
        this.editable = editable;
    }

    @Override
    public ByteArray getContents() {
        return ((RawEditor)burpEditor).getContents();
    }

    @Override
    public void setContents(ByteArray contents) {
        ((RawEditor)burpEditor).setContents(contents);
    }

    @Override
    public HttpResponse getResponse() {
        if(messageType != MessageType.RESPONSE){
            return null;
        }
        HttpResponse result;
        result = fallbackMode ? HttpResponse.httpResponse(ByteArray.byteArray(fallbackArea.getText().getBytes())) : ((HttpResponseEditor)burpEditor).getResponse();
        return result == null ? HttpResponse.httpResponse() : result;
    }

    @Override
    public void setResponse(HttpResponse response) {
        if (fallbackMode) {
            fallbackArea.setText(response.toString());
        } else {
            this.lastContent = response.toByteArray();
            ((HttpResponseEditor)burpEditor).setResponse(response);
        }
    }

    @Override
    public HttpRequest getRequest() {
        if(messageType != MessageType.REQUEST){
            return null;
        }
        HttpRequest result;
        result = fallbackMode ? HttpRequest.httpRequest(ByteArray.byteArray(fallbackArea.getText().getBytes())) : ((HttpRequestEditor)burpEditor).getRequest();
        return result == null ? HttpRequest.httpRequest() : result;
    }

    @Override
    public void setRequest(HttpRequest request) {
        if (fallbackMode) {
            fallbackArea.setText(request.toString());
        } else {
            this.lastContent = request.toByteArray();
            ((HttpRequestEditor)burpEditor).setRequest(request);
        }
    }

    @Override
    public void setSearchExpression(String expression) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setSearchExpression'");
    }

    @Override
    public boolean isModified() {
        return isModified;
    }

    @Override
    public int caretPosition() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'caretPosition'");
    }

    @Override
    public Optional<Selection> selection() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'selection'");
    }

    @Override
    public Component uiComponent() {
        if (fallbackMode) {
            JScrollPane inputScrollPane = new JScrollPane(fallbackArea);
            return inputScrollPane;
        }
        return burpEditor.uiComponent();
    }
}
