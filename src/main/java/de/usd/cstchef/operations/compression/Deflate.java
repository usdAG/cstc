package de.usd.cstchef.operations.compression;

import java.util.zip.Deflater;

import burp.api.montoya.core.ByteArray;

import java.io.ByteArrayOutputStream;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Deflate", category = OperationCategory.COMPRESSION, description = "Deflate input string")

public class Deflate extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        Deflater deflater = new Deflater();
        deflater.setInput(input.getBytes());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream(input.length());
        deflater.finish();

        byte[] buffer = new byte[1024];
        while( !deflater.finished() ) {
            int count = deflater.deflate(buffer);
            outputStream.write(buffer, 0, count);
        }

        outputStream.close();
        return factory.createByteArray(outputStream.toByteArray());
    }
}
