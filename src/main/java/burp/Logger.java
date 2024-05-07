package burp;

import burp.api.montoya.logging.Logging;

public class Logger {

    private static Logger instance;
    private Logging logging;

    public static Logger getInstance() {
        if (Logger.instance == null) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }

    private Logger() {
        init();
    }

    public void init() {
        logging = BurpUtils.getInstance().getApi().logging();
    }

    public void log(String msg) {
        if (this.logging == null) {
            System.out.println(msg);
        } else {
            logging.logToOutput(msg);
        }
    }

    public void err(String msg) {
        if (this.logging == null) {
            System.err.println(msg);
        } else {
            logging.logToError(msg);
        }
    }
}
