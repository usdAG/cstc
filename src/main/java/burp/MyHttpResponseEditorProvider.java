package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import de.usd.cstchef.view.View;

class MyHttpResponseEditorProvider implements HttpResponseEditorProvider
{
    private final View view;

    MyHttpResponseEditorProvider(View view){
        this.view = view;
    }


    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new MyExtensionProvidedHttpResponseEditor(creationContext, view);
    }
}