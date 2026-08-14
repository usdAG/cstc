package de.usd.cstchef.view;

import java.awt.Component;
import java.awt.Container;
import java.util.Optional;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
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
import de.usd.cstchef.Utils;
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

    private boolean hasRawEditor() {
        return burpEditor instanceof RawEditor;
    }

    private boolean hasRequestEditor() {
        return burpEditor instanceof HttpRequestEditor;
    }

    private boolean hasResponseEditor() {
        return burpEditor instanceof HttpResponseEditor;
    }

    private void setEditorText(ByteArray contents) {
        if (fallbackMode) {
            fallbackArea.setText(contents.toString());
            return;
        }

        JTextArea textArea = findTextAreaComponent(burpEditor.uiComponent());
        if (textArea != null) {
            textArea.setText(contents.toString());
        }
    }

    private void persistInput(DocumentEvent e, JTextArea textArea) {
        try {
            RecipePanel recipePanel = (RecipePanel) SwingUtilities.getAncestorOfClass(RecipePanel.class, textArea);
            String persistenceKey = recipePanel != null ? recipePanel.getPersistedInputKey() : operation + "-Input";
            api.persistence().extensionData().setString(persistenceKey, e.getDocument().getText(0, e.getDocument().getLength()));
            isInputRestored = true;
            if(!isChangedViaContextMenu) {
                requestToResponse = null;
            }
        } catch (BadLocationException e1) {
            return;
        }
    }

    public BurpEditorWrapper(CstcMessageEditorController controller, BurpOperation operation, Boolean isInputEditor){
        this.api = BurpUtils.getInstance().getApi();
        this.operation = operation;
        this.lastContent = ByteArray.byteArray("");
        if (BurpUtils.inBurp()) {
            switch(operation){
                case OUTGOING: burpEditor = api.userInterface().createHttpRequestEditor(); break;
                case INCOMING: burpEditor = api.userInterface().createHttpResponseEditor(); break;
                case FORMAT: burpEditor = api.userInterface().createRawEditor(); break;
                default: break;
            }
            fallbackMode = false;
        } else {
            this.fallbackArea = new JTextArea();
            fallbackMode = true;
        }

        Component component = fallbackMode ? fallbackArea : burpEditor.uiComponent();
        JTextArea textArea = isInputEditor ? findTextAreaComponent(component) : null;

        if(textArea != null) {
            textArea.getDocument().addDocumentListener(new DocumentListener() {

                @Override
                public void changedUpdate(DocumentEvent e) {
                    persistInput(e, textArea);
                }

                @Override
                public void insertUpdate(DocumentEvent e) {
                    persistInput(e, textArea);
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    persistInput(e, textArea);
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
        if (fallbackMode) {
            return ByteArray.byteArray(fallbackArea.getText());
        }

        if(hasRawEditor())
            return ((RawEditor)burpEditor).getContents();
        else if(hasRequestEditor()) {
            HttpRequest request = ((HttpRequestEditor)burpEditor).getRequest();
            return request == null ? ByteArray.byteArray() : request.toByteArray();
        }
        else if(hasResponseEditor()) {
            HttpResponse response = ((HttpResponseEditor)burpEditor).getResponse();
            return response == null ? ByteArray.byteArray() : response.toByteArray();
        }
        else
            return ByteArray.byteArray();
    }

    @Override
    public void setContents(ByteArray contents) {
        isChangedViaContextMenu = true;
        this.lastContent = contents;

        if(contents.length() == 0) {
            isChangedViaContextMenu = false;
            return;
        }

        if (fallbackMode) {
            fallbackArea.setText(contents.toString());
        }
        else if(hasRawEditor()) {
            ((RawEditor)burpEditor).setContents(contents);
        }
        else if(hasRequestEditor() && Utils.isHttpRequest(contents))
            ((HttpRequestEditor)burpEditor).setRequest(HttpRequest.httpRequest(contents));
        else if(hasResponseEditor() && Utils.isHttpResponse(contents))
            ((HttpResponseEditor)burpEditor).setResponse(HttpResponse.httpResponse(contents));
        else
            setEditorText(contents);
        isChangedViaContextMenu = false;
    }

    @Override
    public HttpResponse getResponse() {
        if(operation != BurpOperation.INCOMING){
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
        if(operation != BurpOperation.OUTGOING){
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

    @Override
    public void setCaretPosition(int arg0) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setCaretPosition'");
    }
}
