package de.usd.cstchef.operations.compression;

import javax.swing.JComboBox;

import burp.api.montoya.core.ByteArray;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.wrapper.GZIPOutputStreamWrapper;

@OperationInfos(name = "GZIP", category = OperationCategory.COMPRESSION, description = "Compresses the input using GZIP.")
public class Gzip extends Operation {

    private JComboBox<Integer> compressionLevelBox;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        //GZIPOutputStream gzos = new GZIPOutputStream(out);
        GZIPOutputStreamWrapper gzos = new GZIPOutputStreamWrapper(out);
        gzos.setCompressionLevel((int)compressionLevelBox.getSelectedItem());
        ByteArrayInputStream in = new ByteArrayInputStream(input.getBytes());

        byte[] buffer = new byte[1024];
        int len;
        while ((len = in.read(buffer)) > 0) {
            gzos.write(buffer, 0, len);
        }

        in.close();
        gzos.close();
        out.close();
        return factory.createByteArray(out.toByteArray());
    }

    @Override
    public void createUI()
    {
        Integer[] compressionLevel = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        this.compressionLevelBox = new JComboBox<>(compressionLevel);
        this.compressionLevelBox.setSelectedIndex(5);
        this.addUIElement("Compression Level", this.compressionLevelBox);
    }

}
