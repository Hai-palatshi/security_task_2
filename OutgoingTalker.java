package il.ac.kinneret.mjmay.hls.hlsjava.model;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.logging.Logger;

/**
 * Sends outgoing messages asynchronously to the father
 * @author Michael J. May
 * @version 1.0
 */
public class OutgoingTalker extends Thread{

    Logger logger;

    /**
     * Creates the outgoing talker thread
     */
    public OutgoingTalker()
    {
        logger = Logger.getLogger(OutgoingTalker.class.getName());
    }

    /**
     * Runs the thread.  Listens on the outgoing message queue and sends commands to the father from it
     */
    @Override
    public void run() {
        try {
            // wait until there's something to send to the father
            while (!this.isInterrupted()) {
                String messageToSend = Common.fatherMessages.take();
                // open a socket to the father
                Socket clientSocket = new Socket(Common.fatherIp, Common.fatherPort);
                PrintWriter pwOut = new PrintWriter(clientSocket.getOutputStream());

                // TODO: change here to send encrypt message
                pwOut.println(Encryption.encryptMessage(messageToSend));
                // all done
                pwOut.flush();
                pwOut.close();
                clientSocket.close();
                logger.info("Sent message to father: " + messageToSend);
                LoggerFile.getInstance().info("Sent message to father: " + messageToSend);

            }
        } catch (InterruptedException | IOException iox)
        {
            logger.severe("Error in thread sending to father: " + iox.getMessage());
            try {
                LoggerFile.getInstance().info("Error in thread sending to father: " + iox.getMessage());
            } catch (IOException e) {
                e.printStackTrace();
            }

            return;
        }
    }
}
