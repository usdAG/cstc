package de.usd.cstchef.operations.compression;

import java.util.zip.GZIPOutputStream;

import burp.api.montoya.core.ByteArray;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "GZIP", category = OperationCategory.COMPRESSION, description = "Compresses the input using GZIP.")
public class Gzip extends Operation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzos = new GZIPOutputStream(out);
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

}
