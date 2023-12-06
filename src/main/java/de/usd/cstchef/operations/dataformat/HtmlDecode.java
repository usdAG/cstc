package de.usd.cstchef.operations.dataformat;

import java.nio.charset.StandardCharsets;

import org.apache.commons.text.StringEscapeUtils;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTML Decode", category = OperationCategory.DATAFORMAT, description = "HTML Decode")
public class HtmlDecode extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        return factory.createByteArray(StringEscapeUtils.unescapeHtml4(input.toString()));
    }

}
