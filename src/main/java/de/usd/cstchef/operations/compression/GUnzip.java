package de.usd.cstchef.operations.compression;

import java.util.zip.GZIPInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "GUNZIP", category = OperationCategory.COMPRESSION, description = "Decompresses the input using GZIP.")
public class GUnzip extends Operation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(input);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gis = new GZIPInputStream(in);

        byte[] buffer = new byte[1024];
        int len;
        while((len = gis.read(buffer)) != -1){
            out.write(buffer, 0, len);
        }

        gis.close();
        out.close();
        in.close();
        return out.toByteArray();
    }

}
