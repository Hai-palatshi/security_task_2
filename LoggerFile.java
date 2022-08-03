package il.ac.kinneret.mjmay.hls.hlsjava.model;

import java.io.IOException;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
/**
 * A Singleton class that holds logger object, so that logging to a file can be performed
 * @authors Sasha Chernin & Hai Palatshi
 */
public class LoggerFile {
    private static LoggerFile loggerFile = null;

    public Logger logger;

    /**
     * Constructor function that configures the logger
     */
    public LoggerFile() throws IOException {
        logger= Logger.getLogger("MyLog");

        FileHandler fh;
        System.setProperty("java.util.logging.SimpleFormatter.format", "[%1$tF %1$tT] %5$s %n");
        try {

            // This block configure the logger with handler and formatter
            fh = new FileHandler("./MyLogFile.log");
            logger.addHandler(fh);
            SimpleFormatter formatter = new SimpleFormatter();
            fh.setFormatter(formatter);
            logger.setUseParentHandlers(false);

            // the following statement is used to log any messages
            logger.info("Server is up");

        } catch (SecurityException | IOException e) {
            e.printStackTrace();
            System.out.println("couldn't set up log file");
        }
    }

    /**
     * a function that makes this class a singleton
     * @return The single instance of this class
     */
    public static Logger getInstance() throws IOException {
        if (loggerFile == null)
            loggerFile = new LoggerFile();

        return loggerFile.logger;
    }



}
