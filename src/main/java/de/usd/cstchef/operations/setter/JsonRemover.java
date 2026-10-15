package de.usd.cstchef.operations.setter;

import javax.swing.JTextField;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import com.jayway.jsonpath.spi.json.JsonProvider;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(
    name = "Remove JSON",
    category = OperationCategory.SETTER,
    description = """
            <html>
              <body>
                <p>
                  Remove JSON key-value pairs and arrays based on the keys.
                </p>
                <p>
                  This operation uses JsonPath expressions. More information: https://github.com/json-path/JsonPath
                </p>

                Remove values from JSON.

                <h2>Operators</h2>
                <table cellspacing="0" cellpadding="3">
                  <tr><td><code>$</code></td><td>The root element to query. This starts all path expressions.</td></tr>
                  <tr><td><code>@</code></td><td>The current node being processed by a filter predicate.</td></tr>
                  <tr><td><code>*</code></td><td>Wildcard. Available anywhere a name or numeric are required.</td></tr>
                  <tr><td><code>..</code></td><td>Deep scan. Available anywhere a name is required.</td></tr>
                  <tr><td><code>.&lt;name&gt;</code></td><td>Dot-notated child.</td></tr>
                  <tr><td><code>['&lt;name&gt;' (, '&lt;name&gt;')]</code></td><td>Bracket-notated child or children.</td></tr>
                  <tr><td><code>[&lt;number&gt; (, &lt;number&gt;)]</code></td><td>Array index or indexes.</td></tr>
                  <tr><td><code>[start:end]</code></td><td>Array slice operator.</td></tr>
                  <tr><td><code>[?(&lt;expression&gt;)]</code></td><td>Filter expression. The expression must evaluate to a boolean value.</td></tr>
                </table>

                <h2>Functions</h2>
                <table cellspacing="0" cellpadding="3">
                  <tr><td><code>min()</code></td><td>Provides the minimum value of an array of numbers.</td><td><code>Double</code></td></tr>
                  <tr><td><code>max()</code></td><td>Provides the maximum value of an array of numbers.</td><td><code>Double</code></td></tr>
                  <tr><td><code>avg()</code></td><td>Provides the average value of an array of numbers.</td><td><code>Double</code></td></tr>
                  <tr><td><code>stddev()</code></td><td>Provides the standard deviation value of an array of numbers.</td><td><code>Double</code></td></tr>
                  <tr><td><code>length()</code></td><td>Provides the length of an array.</td><td><code>Integer</code></td></tr>
                  <tr><td><code>sum()</code></td><td>Provides the sum value of an array of numbers.</td><td><code>Double</code></td></tr>
                  <tr><td><code>keys()</code></td><td>Provides the property keys (an alternative for terminal tilde <code>~</code>).</td><td><code>Set&lt;E&gt;</code></td></tr>
                  <tr><td><code>concat(X)</code></td><td>Provides a concatenated version of the path output with a new item.</td><td><code>like input</code></td></tr>
                  <tr><td><code>append(X)</code></td><td>Adds an item to the JSON path output array.</td><td><code>like input</code></td></tr>
                  <tr><td><code>first()</code></td><td>Provides the first item of an array.</td><td><code>Depends on the array</code></td></tr>
                  <tr><td><code>last()</code></td><td>Provides the last item of an array.</td><td><code>Depends on the array</code></td></tr>
                  <tr><td><code>index(X)</code></td><td>Provides the item of an array at index <code>X</code>. If <code>X</code> is negative, the index is counted from the end.</td><td><code>Depends on the array</code></td></tr>
                </table>

                <h2>Filter Operators</h2>
                <table cellspacing="0" cellpadding="3">
                  <tr><td><code>==</code></td><td>Left is equal to right (note that <code>1</code> is not equal to <code>'1'</code>).</td></tr>
                  <tr><td><code>!=</code></td><td>Left is not equal to right.</td></tr>
                  <tr><td><code>&lt;</code></td><td>Left is less than right.</td></tr>
                  <tr><td><code>&lt;=</code></td><td>Left is less than or equal to right.</td></tr>
                  <tr><td><code>&gt;</code></td><td>Left is greater than right.</td></tr>
                  <tr><td><code>&gt;=</code></td><td>Left is greater than or equal to right.</td></tr>
                  <tr><td><code>=~</code></td><td>Left matches the regular expression <code>[?(@.name =~ /foo.*?/i)]</code>.</td></tr>
                  <tr><td><code>in</code></td><td>Left exists in right: <code>[?(@.size in ['S', 'M'])]</code>.</td></tr>
                  <tr><td><code>nin</code></td><td>Left does not exist in right.</td></tr>
                  <tr><td><code>subsetof</code></td><td>Left is a subset of right: <code>[?(@.sizes subsetof ['S', 'M', 'L'])]</code>.</td></tr>
                  <tr><td><code>anyof</code></td><td>Left has an intersection with right: <code>[?(@.sizes anyof ['M', 'L'])]</code>.</td></tr>
                  <tr><td><code>noneof</code></td><td>Left has no intersection with right: <code>[?(@.sizes noneof ['M', 'L'])]</code>.</td></tr>
                  <tr><td><code>size</code></td><td>The size of left (array or string) should match right.</td></tr>
                  <tr><td><code>empty</code></td><td>Left (array or string) should be empty.</td></tr>
                </table>
              </body>
            </html>
            """
)
public class JsonRemover extends Operation {

    static JsonProvider provider;

    protected JTextField fieldTxt;

    public JsonRemover(){
        this(new String());
    }

    public JsonRemover(String key) {
        super();
        if (JsonRemover.provider == null) {
            JsonRemover.provider = Configuration.defaultConfiguration().jsonProvider();
        }
        this.setKey(key);
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        if (fieldTxt.getText().equals("")) {
            return input;
        }
            
        DocumentContext document = JsonPath.parse(input.toString());

        document.delete(fieldTxt.getText());

        return factory.createByteArray(document.jsonString());
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
    
    public void setKey(String key){
        this.fieldTxt.setText(key);
    }

}
