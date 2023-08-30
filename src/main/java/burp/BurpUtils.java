package burp;

import burp.api.montoya.MontoyaApi;

public class BurpUtils {

    private static BurpUtils instance;
    private MontoyaApi api;

    public static BurpUtils getInstance() {
        if (BurpUtils.instance == null) {
            BurpUtils.instance = new BurpUtils();
        }
        return BurpUtils.instance;
    }

    private BurpUtils() {
    }

    public void init(MontoyaApi api) {
        this.api = api;
    }

    public MontoyaApi getApi() throws IllegalAccessError {
        if (this.api == null) {
            throw new IllegalAccessError("Only works within burpsuite");
        }
        return api;
    }

    public static boolean inBurp() {
        try {
            BurpUtils.getInstance().getApi();
            return true;
        } catch (IllegalAccessError e) {
            return false;
        }
    }

}
