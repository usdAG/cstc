package burp;

public class BurpUtils {

    private static BurpUtils instance;
    private IBurpExtenderCallbacks callbacks;

    public static BurpUtils getInstance() {
        if (BurpUtils.instance == null) {
            BurpUtils.instance = new BurpUtils();
        }
        return BurpUtils.instance;
    }

    private BurpUtils() {
    }

    public void init(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    public IBurpExtenderCallbacks getCallbacks() throws IllegalAccessError {
        if (this.callbacks == null) {
            throw new IllegalAccessError("Only works within burpsuite");
        }
        return callbacks;
    }

    public static boolean inBurp() {
        try {
            BurpUtils.getInstance().getCallbacks();
            return true;
        } catch (IllegalAccessError e) {
            return false;
        }
    }

}
