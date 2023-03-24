package burp;

import java.io.OutputStream;
import java.io.PrintWriter;

public class Logger {

    private static Logger instance;

    private PrintWriter stdout;
    private PrintWriter stderr;

    public static Logger getInstance() {
        if (Logger.instance == null) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }

    private Logger() {

    }

    public void init(OutputStream stdOut, OutputStream stdErr) {
        this.stdout = new PrintWriter(stdOut, true);
        this.stderr = new PrintWriter(stdErr, true);
    }

    public void log(String msg) {
        if (this.stdout == null) {
            System.out.println(msg);
        } else {
            this.stdout.println(msg);
        }
    }

    public void err(String msg) {
        if (this.stderr == null) {
            System.err.println(msg);
        } else {
            this.stderr.println(msg);
        }
    }
}
