package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(
    name = "Get HTTP XML",
    category = OperationCategory.EXTRACTORS,
    description = """
            <html>
              <body>
                <p>
                  This operation uses XPath expressions. More information: https://www.w3.org/TR/xpath/
                </p>

                <h2>Selecting Nodes</h2>
                <table cellspacing="0" cellpadding="3">
                  <tr><td><code>nodename</code></td><td>Selects all nodes with the name <code>nodename</code>.</td></tr>
                  <tr><td><code>/</code></td><td>Selects from the root node.</td></tr>
                  <tr><td><code>//</code></td><td>Selects nodes in the document from the current node that match the selection no matter where they are.</td></tr>
                  <tr><td><code>.</code></td><td>Selects the current node.</td></tr>
                  <tr><td><code>..</code></td><td>Selects the parent of the current node.</td></tr>
                  <tr><td><code>@</code></td><td>Selects attributes.</td></tr>
                </table>

                <h2>Predicates</h2>
                <table cellspacing="0" cellpadding="3">
                  <tr><td><code>/parent/child[1]</code></td><td>Selects the first <code>child</code> element that is the child of the <code>parent</code> element.</td></tr>
                  <tr><td><code>/parent/child[last()]</code></td><td>Selects the last <code>child</code> element that is the child of the <code>parent</code> element.</td></tr>
                  <tr><td><code>/parent/child[last()-1]</code></td><td>Selects the last but one <code>child</code> element that is the child of the <code>parent</code> element.</td></tr>
                  <tr><td><code>/parent/child[position()&lt;3]</code></td><td>Selects the first two <code>child</code> elements that are children of the <code>parent</code> element.</td></tr>
                  <tr><td><code>//child[@attr]</code></td><td>Selects all the <code>child</code> elements that have an attribute named <code>attr</code>.</td></tr>
                  <tr><td><code>//child[@attr='xy']</code></td><td>Selects all the <code>child</code> elements that have an <code>attr</code> attribute with a value of <code>xy</code>.</td></tr>
                  <tr><td><code>/parent/child[value&gt;35.00]</code></td><td>Selects all the <code>child</code> elements of the <code>parent</code> element that have a <code>value</code> element with a value greater than <code>35.00</code>.</td></tr>
                  <tr><td><code>/parent/child[value&gt;35.00]/leaf</code></td><td>Selects all the <code>leaf</code> elements of the <code>child</code> elements of the <code>parent</code> element that have a <code>value</code> element with a value greater than <code>35.00</code>.</td></tr>
                </table>

                <h2>Selecting Unknown Nodes</h2>
                <table cellspacing="0" cellpadding="3">
                  <tr><td><code>*</code></td><td>Matches any element node.</td></tr>
                  <tr><td><code>@*</code></td><td>Matches any attribute node.</td></tr>
                  <tr><td><code>node()</code></td><td>Matches any node of any kind.</td></tr>
                </table>
              </body>
            </html>
            """
)
public class HttpXmlExtractor extends Operation {

    protected VariableTextField path;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        String p = this.path.getText();

        if(p.trim().isEmpty()) {
            return input;
        }

        if(messageType == MessageType.REQUEST) {
            return Utils.xmlExtractor(factory, factory.createHttpRequest(input).body(), p);
        }
        else if(messageType == MessageType.RESPONSE) {
            return Utils.xmlExtractor(factory, factory.createHttpResponse(input).body(), p);
        }
        else {
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.path = new VariableTextField();
        this.addUIElement("Path", this.path);
    }
}
