package de.usd.cstchef.view;

import java.awt.Component;
import java.util.Optional;

import javax.swing.JScrollPane;
import javax.swing.JTextArea;

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

    private boolean isModified;
    private boolean editable;
    private BurpOperation operation;
    private MontoyaApi api;
    private boolean fallbackMode;
    private JTextArea fallbackArea;
    private Editor burpEditor;
    private ByteArray lastContent;
    private RecipePanel recipePanel;

    public BurpEditorWrapper(CstcMessageEditorController controller, BurpOperation operation, RecipePanel panel){
        this.api = BurpUtils.getInstance().getApi();
        this.operation = operation;
        this.recipePanel = panel;
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
    }

    @Override
    public void setEditable(boolean editable) {
        this.editable = editable;
    }

    @Override
    public ByteArray getContents() {
        if(operation == BurpOperation.FORMAT)
            return ((RawEditor)burpEditor).getContents();
        else if(operation == BurpOperation.OUTGOING)
            return ((HttpRequestEditor)burpEditor).getRequest().toByteArray();
        else if(operation == BurpOperation.INCOMING)
            return ((HttpResponseEditor)burpEditor).getResponse().toByteArray();
        else
            return ByteArray.byteArray();
    }

    @Override
    public void setContents(ByteArray contents) {
        this.lastContent = contents;
        if(operation == BurpOperation.OUTGOING)
            ((HttpRequestEditor)burpEditor).setRequest(HttpRequest.httpRequest(contents));
        else if(operation == BurpOperation.INCOMING)
            ((HttpResponseEditor)burpEditor).setResponse(HttpResponse.httpResponse(contents));
        else
            ((RawEditor)burpEditor).setContents(contents);
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
        if (fallbackMode) {
            fallbackArea.setText(response.toString());
        } else {
            this.lastContent = response.toByteArray();
            ((HttpResponseEditor)burpEditor).setResponse(response);
        }
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
}
