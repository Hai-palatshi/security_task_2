package il.ac.kinneret.mjmay.hls.hlsjava.model;

import javafx.collections.ObservableList;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Contains shared variables and functions for the tool
 * @author Michael J. May
 * @version 1.0
 */
public class Common {

    /**
     * The server socket instance for incoming conversations
     */
    public static ServerSocket serverSocket = null;
    /**
     * Whether we are listening now or not
     */
    public static boolean isListening = false;
    /**
     * Whether we are the root (fatherless) or not
     */
    public static boolean isRoot = false;
    /**
     * The list of files stored locally and at children
     */
    public static HashMap<String, FileEntry> fileList = null;
    /**
     * The IP address for the father node
     */
    public static InetAddress fatherIp;
    /**
     * The port for the father node
     */
    public static int fatherPort;
    /**
     * The local IP listening address
     */
    public static InetAddress localIp;
    /**
     * The local incoming listening port
     */
    public static int localPort;
    /**
     * Used for mutual exclusion on the file lists
     */
    public static final Object locker = new Object();
    /**
     * Constant for ADD message - it's structured ADD IP:Port Filename
     */
    public final static String ADD_COMMAND = "ADD";
    /**
     * Constant for DELETE mesasage - it's structured DELETE IP:Port Filename
     */
    public final static String DELETE_COMMAND = "DELETE";
    /**
     * Constant for LOOKUP message - it's structured LOOKUP Filename
     */
    public final static String LOOKUP_COMMAND = "LOOKUP";
    /**
     * Response for a file that is not found
     */
    public final static String NOTFOUND = "NotFound";
    /**
     * Response for a file that is found locally
     */
    public final static String LOCAL = "Local";
    /**
     * Constant for RETRIEVE message - it's structured RETRIEVE filename
     */
    public final static String RETRIEVE_COMMAND = "RETRIEVE";
    /**
     * Used to queue messages to be sent to the father asynchronously
     */
    public static LinkedBlockingQueue<String> fatherMessages = new LinkedBlockingQueue<>();
    /**
     * Used for displaying file entries in the list view on the GUI
     */
    public static ObservableList<FileEntry> fileEntries;

    /**
     * Removes the leading / character from an IP address if it has one
     * @param address The IP address that might begin with a / character
     * @return The address as is or with the leading / removed if there is one
     */
    public static String ipRemoveSlash (String address)
    {
        // trim it first
        address.trim();
        // check if it begins with a /
        if (address.contains("/"))
        {
            return address.substring(1);
        } else
        {
            return address;
        }
    }

    // ADD message format: ADD IP:Port Filename
    // DELETE message format: DELETE IP:Port Filename
    // lookup message format: LOOKUP Filename
    // retrieve message format: RETRIEVE filename
    //  If the file isn't found, send back NotFound
    //  If it's found, sent back Local followed by the contents
}
