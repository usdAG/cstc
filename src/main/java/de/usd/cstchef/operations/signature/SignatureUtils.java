package de.usd.cstchef.operations.signature;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureUtils {

    private static SignatureUtils instance;

    private List<String> algos;

    private SignatureUtils() {
        algos = new ArrayList<String>();;
        getSignatureInfos();
    }

    private void getSignatureInfos() {
        for (Provider provider : Security.getProviders())
            for (Service service : provider.getServices())
                if (service.getType().equals("Signature"))
                    algos.add(service.getAlgorithm());
    }

    public static SignatureUtils getInstance() {
        if (instance == null) {
            instance = new SignatureUtils();
        }
        return instance;
    }

    public String[] getAlgos() {
        return algos.toArray(new String[0]);
    }
    public String[] getAlgos(String s) {
        List<String> rsaAlgos = algos.stream().filter(p -> p.contains(s)).collect(Collectors.toList());
        return rsaAlgos.toArray(new String[0]);
    }
    
}
