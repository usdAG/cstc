package de.usd.cstchef.operations.dataformat;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Url Decode", category = OperationCategory.DATAFORMAT, description = "Url decoding")
public class UrlDecode extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        MontoyaApi api = BurpUtils.getInstance().getApi();

        ByteArray result = api.utilities().urlUtils().decode(input);
        return result;
    }

}
