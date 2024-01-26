package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Method", category = OperationCategory.EXTRACTORS, description = "Extracts the method of a HTTP request.")
public class HttpMethodExtractor extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        try {
            MontoyaApi api = BurpUtils.getInstance().getApi();
            int length = input.length();

            int methodEnd = api.utilities().byteUtils().indexOf(input.getBytes(), " ".getBytes(), false, 0, length);
            ByteArray result = BurpUtils.subArray(input, 0, methodEnd);

            return result;

        } catch (Exception e) {
            throw new IllegalArgumentException("Provided input is not a valid http request.");
        }
    }
}
