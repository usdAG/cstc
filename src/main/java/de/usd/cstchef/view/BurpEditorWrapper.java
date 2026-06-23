package de.usd.cstchef.view;

import java.awt.Component;
import java.awt.Container;
import java.util.Optional;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;

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
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

public class BurpEditorWrapper implements HttpRequestEditor, HttpResponseEditor, RawEditor{

    private BurpOperation operation;
    private MontoyaApi api;
    private boolean fallbackMode;
    private JTextArea fallbackArea;
    private Editor burpEditor;
    private ByteArray lastContent;
    private ByteArray requestToResponse;
    private boolean isChangedViaContextMenu = false;
    private boolean isInputRestored = false;

    public BurpEditorWrapper(CstcMessageEditorController controller, BurpOperation operation, Boolean isInputEditor){
        this.api = BurpUtils.getInstance().getApi();
        this.operation = operation;
        this.lastContent = ByteArray.byteArray("");
        if (BurpUtils.inBurp()) {
            switch(operation){
                case INCOMING_PROXY_REQUEST:
                case OUTGOING_HTTP_REQUEST: burpEditor = api.userInterface().createHttpRequestEditor(); break;
                case OUTGOING_PROXY_RESPONSE:
                case INCOMING_HTTP_RESPONSE: burpEditor = api.userInterface().createHttpResponseEditor(); break;
                case FORMAT: burpEditor = api.userInterface().createRawEditor(); break;
                default: break;
            }
            fallbackMode = false;
        } else {
            this.fallbackArea = new JTextArea();
            fallbackMode = true;
        }

        Component component = burpEditor.uiComponent();
        JTextArea textArea = isInputEditor ? findTextAreaComponent(component) : null;

        if(textArea != null) {
            textArea.getDocument().addDocumentListener(new DocumentListener() {

                @Override
                public void changedUpdate(DocumentEvent e) {
                    try {
                        if(isInputRestored) {
                            api.persistence().extensionData().setString(operation + "Input", e.getDocument().getText(0, e.getDocument().getLength()));
                        }
                        if(!isChangedViaContextMenu) {
                            requestToResponse = null;
                        }
                    } catch (BadLocationException e1) {
                        return;
                    }
                }

                @Override
                public void insertUpdate(DocumentEvent e) {
                    return;
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    return;
                }
            });
        }
    }

    public void setInputRestoredTrue() {
        this.isInputRestored = true;
    }

    public ByteArray getRequestToResponse() {
        return this.requestToResponse;
    }

    public void setRequestToResponse(ByteArray requestToResponse) {
        this.requestToResponse = requestToResponse;
    }

    @Override
    public ByteArray getContents() {
        if(operation == BurpOperation.FORMAT)
            return ((RawEditor)burpEditor).getContents();
        else if(operation == BurpOperation.INCOMING_PROXY_REQUEST || operation == BurpOperation.OUTGOING_HTTP_REQUEST)
            return ((HttpRequestEditor)burpEditor).getRequest().toByteArray();
        else if(operation == BurpOperation.INCOMING_HTTP_RESPONSE || operation == BurpOperation.OUTGOING_PROXY_RESPONSE)
            return ((HttpResponseEditor)burpEditor).getResponse().toByteArray();
        else
            return ByteArray.byteArray();
    }

    @Override
    public void setContents(ByteArray contents) {
        isChangedViaContextMenu = true;
        this.lastContent = contents;
        if(operation == BurpOperation.INCOMING_PROXY_REQUEST || operation == BurpOperation.OUTGOING_HTTP_REQUEST)
            ((HttpRequestEditor)burpEditor).setRequest(HttpRequest.httpRequest(contents));
        else if(operation == BurpOperation.INCOMING_HTTP_RESPONSE || operation == BurpOperation.OUTGOING_PROXY_RESPONSE)
            ((HttpResponseEditor)burpEditor).setResponse(HttpResponse.httpResponse(contents));
        else
            ((RawEditor)burpEditor).setContents(contents);
        isChangedViaContextMenu = false;
    }

    @Override
    public HttpResponse getResponse() {
        if(operation != BurpOperation.INCOMING_HTTP_RESPONSE && operation != BurpOperation.OUTGOING_PROXY_RESPONSE){
            return null;
        }
        HttpResponse result;
        result = fallbackMode ? HttpResponse.httpResponse(ByteArray.byteArray(fallbackArea.getText().getBytes())) : ((HttpResponseEditor)burpEditor).getResponse();
        return result == null ? HttpResponse.httpResponse() : result;
    }

    @Override
    public void setResponse(HttpResponse response) {
        isChangedViaContextMenu = true;
        if (fallbackMode) {
            fallbackArea.setText(response.toString());
        } else {
            this.lastContent = response.toByteArray();
            ((HttpResponseEditor)burpEditor).setResponse(response);
        }
        isChangedViaContextMenu = false;
    }

    @Override
    public HttpRequest getRequest() {
        if(operation != BurpOperation.INCOMING_PROXY_REQUEST && operation != BurpOperation.OUTGOING_HTTP_REQUEST){
            return null;
        }
        HttpRequest result;
        result = fallbackMode ? HttpRequest.httpRequest(ByteArray.byteArray(fallbackArea.getText().getBytes())) : ((HttpRequestEditor)burpEditor).getRequest();
        return result == null ? HttpRequest.httpRequest() : result;
    }

    @Override
    public void setRequest(HttpRequest request) {
        isChangedViaContextMenu = true;
        if (fallbackMode) {
            fallbackArea.setText(request.toString());
        } else {
            this.lastContent = request.toByteArray();
            ((HttpRequestEditor)burpEditor).setRequest(request);
        }
        isChangedViaContextMenu = false;
    }

    @Override
    public void setEditable(boolean editable) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setEditable'");
    }

    @Override
    public void setSearchExpression(String expression) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setSearchExpression'");
    }

    @Override
    public boolean isModified() {
        boolean result = this.getContents().equals(lastContent);
        lastContent = this.getContents();
        return result;
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

    /* Find JTextArea of the Editor to attach the DocumentListener to */
    private JTextArea findTextAreaComponent(Component component) {
        if (component instanceof JTextArea) {
            return (JTextArea) component;
        } else if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                JTextArea result = findTextAreaComponent(child);
                if (result != null) {
                    return result;
                }
            }
        }
        return null;
    }
}
