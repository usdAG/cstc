package de.usd.cstchef.operations.dataformat;

import java.io.ByteArrayOutputStream;

import javax.swing.JCheckBox;

import org.bouncycastle.util.encoders.Hex;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Url Encode", category = OperationCategory.DATAFORMAT, description = "Url encode")
public class UrlEncode extends Operation {

    private JCheckBox checkbox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        ByteArray result = null;
        MontoyaApi api = BurpUtils.getInstance().getApi();
        if( checkbox.isSelected() ) {

            ByteArray delimiter = ByteArray.byteArray("%");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(delimiter.getBytes());

            for (int i = 0; i < input.length() - 1; i++) {
                out.write(Hex.encode( new byte[] { input.getByte(i) }));
                out.write(delimiter.getBytes());
            }

            out.write(Hex.encode(new byte[] { input.getByte(input.length() - 1) }));
            result = ByteArray.byteArray(out.toByteArray());

        } else {
            //TODO: double conversion!
            result = api.utilities().urlUtils().encode(input);
        }

        return result;
    }

    @Override
    public void createUI() {
        this.checkbox = new JCheckBox("Encode all");
        this.checkbox.setSelected(false);
        this.addUIElement(null, this.checkbox, "checkbox1");
    }
}
