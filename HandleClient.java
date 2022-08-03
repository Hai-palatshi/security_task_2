package il.ac.kinneret.mjmay.hls.hlsjava.model;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * Handles a single incoming client or child connection to receive requests or commands.
 * @author Michael J. May
 * @version 1.0
 */
public class HandleClient extends Thread {

    private Socket clientSocket;
    Logger logger;

    /**
     * Creates an object to handle a client connection
     * @param socket The client connection that we're going to work with
     */
    public HandleClient (Socket socket)
    {
        this.clientSocket = socket;
        logger = Logger.getLogger(HandleClient.class.getName());
    }

    /**
     * Runs the handle client logic.  Handles a single session from the client or child.
     */
    @Override
    public void run() {

        BufferedReader brIn = null;
        PrintWriter pwOut = null;
        try {
            brIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            pwOut = new PrintWriter(clientSocket.getOutputStream());
        } catch (IOException iox)
        {
            // can't communicate, just shut down
            logger.severe("Error communicating with client: " + iox.getMessage());
            try {
                LoggerFile.getInstance().info("Error communicating with client: " + iox.getMessage());
            } catch (IOException e) {
                e.printStackTrace();
            }

            try { clientSocket.close();} catch (Exception ex) {}
            return;
        }

        try {
            // see what the client wants
            String encCommandLine = brIn.readLine();
            String commandLine = null;
            try {
                commandLine = Encryption.decryptMessage(encCommandLine);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
                logger.info("Can't decrypt message");
                commandLine=  "error";
            }
            logger.info("Received command: " + commandLine);
            LoggerFile.getInstance().info("Received command: " + commandLine);

            // parse the command
            String command = commandLine.split(" ")[0].toUpperCase();

            switch (command)
            {
                case Common.ADD_COMMAND:
                    try {
                        performAdd(commandLine);
                    } catch (InterruptedException ie)
                    {
                        logger.severe("Error sending message to father: " + ie.getMessage());
                        LoggerFile.getInstance().info("Error sending message to father: " + ie.getMessage());

                    }
                    break;

                case Common.DELETE_COMMAND:
                    try {
                        performDelete(commandLine);
                    } catch (InterruptedException ie) {
                        logger.severe("Error sending message to father: " + ie.getMessage());
                        LoggerFile.getInstance().info("Error sending message to father: " + ie.getMessage());

                    }
                    break;

                case Common.LOOKUP_COMMAND:
                    performLookup(commandLine, pwOut);
                    break;

                case Common.RETRIEVE_COMMAND:
                    // need to write raw bytes on this, so send the raw stream too
                    performRetrieve(commandLine, pwOut, clientSocket.getOutputStream());
                    break;

                case "WRONGMAC":
                    // wrong mac received. user is notified in the logger.
                    pwOut.println(Encryption.encryptMessage("WRONGMAC"));

                    break;

                default:
                    pwOut.println(Encryption.encryptMessage("ERROR: unrecognized command"));
                    logger.info("Received unrecognized command: " + commandLine);
                    LoggerFile.getInstance().info("Received unrecognized command: " + commandLine);

                    break;
            }
            // we did the command, so shut the session
            brIn.close();
            pwOut.close();
            clientSocket.close();
        } catch (IOException | ArrayIndexOutOfBoundsException iox)
        {
            // something went wrong again, do quit
            logger.info("Error reading or parsing  command from client " + iox.getMessage());
            try {
                LoggerFile.getInstance().info("Error reading or parsing  command from client " + iox.getMessage());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Send back the contents of the file sent.  If the file isn't found, first NotFound is sent and then the session is
     * closed. if the file is found, first Local is sent and then the file contents follow
     * @param commandLine The command as supplied
     * @param pwOut The output PrintWriter instance to write the NotFound or Local opening message
     * @param outputStream Where the file's contents will be sent
     */
    private void performRetrieve(String commandLine, PrintWriter pwOut, OutputStream outputStream) {
        // see if the file is found locally
        String fileName = commandLine.substring(commandLine.indexOf(" ")+1);
        if (Common.fileList.containsKey(fileName) && Common.fileList.get(fileName).getIsLocal())
        {
            // open the file locally
            FileEntry fileEntry = Common.fileList.get(fileName);
            File localFile = new File(new LocationList(fileEntry.getFileLocation()).getLocalLocation(), fileName+".enc");
            if (localFile.exists() && localFile.isFile())
            {
                // send it back
                pwOut.println(Encryption.encryptMessage(Common.LOCAL));
                pwOut.flush();
                // send it in a byte buffer
                byte[] buffer = new byte[4096];
                int read = 0;
                try {
                    FileInputStream fis = new FileInputStream(localFile);
                    while ((read = fis.read(buffer)) > 0)
                    {
                        // output the bytes
                        outputStream.write(buffer, 0, read);
                    }
                    // we're done
                    fis.close();

                    //decrypt file
                    logger.info("Finished sending file " + fileName + " to remote node");
                    LoggerFile.getInstance().info("Finished sending file " + fileName + " to remote node");

                } catch (IOException iox)
                {
                    pwOut.println(Encryption.encryptMessage(Common.NOTFOUND));
                    pwOut.flush();
                    // something went wrong!
                    logger.warning("Received retrieve command for file " + fileName + ", but it couldn't be sent due to " + iox.getMessage());
                    try {
                        LoggerFile.getInstance().info("Received retrieve command for file " + fileName + ", but it couldn't be sent due to " + iox.getMessage());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            }
            else
            {
                // it's not here or not found
                pwOut.println(Encryption.encryptMessage(Common.NOTFOUND));
                pwOut.flush();
                // something went wrong!
                logger.warning("Received retrieve command for file " + fileName + ", but it couldn't be sent because it's not found locally");
                try {
                    LoggerFile.getInstance().info("Received retrieve command for file " + fileName + ", but it couldn't be sent because it's not found locally");
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }
    }

    /**
     * Performs a search for a specific file across the network
     * @param commandLine The lookup command that is received which hold the file's name we are looking for
     * @param pwOut PrintWriter object that allows us to send messages to other nodes
     */
    private void performLookup(String commandLine, PrintWriter pwOut) {
        // get the file name
        String fileName = commandLine.substring(commandLine.indexOf(" ") + 1); // it's the part from the second space and onward
        // see if there is a file by that name in the index
        if (Common.fileList.containsKey(fileName)) {
            FileEntry fileEntry = Common.fileList.get(fileName);
            LocationList locations = new LocationList(fileEntry.getFileLocation());
            // see if this entry is local
            if (fileEntry.getIsLocal()) {
                // send back the list with "Local" in the beginning and then the IPs afterward
                pwOut.println(Encryption.encryptMessage(Common.LOCAL + ";" + locations.toNonLocalString()));
            } else {
                // it's all non-local, so we can just send the list
                pwOut.println(Encryption.encryptMessage(locations.toString()));
                logger.info("Sent back a list of potential locations to the file requested : " + fileName + " " + locations);
                try {
                    LoggerFile.getInstance().info("Sent back a list of potential locations to the file requested : " + fileName + " " + locations);
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }
        // it's not here, see if we're the root
        else if (Common.isRoot) {
            // it just doesn't exist, send back not found
            pwOut.println(Encryption.encryptMessage(Common.NOTFOUND));
            logger.info("Sent back a notfound response to the file requested : " + fileName);
            try {
                LoggerFile.getInstance().info("Sent back a notfound response to the file requested : " + fileName);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        // we're not the root and it's not found, so send the father's IP
        else  {
            pwOut.println(Encryption.encryptMessage(Common.fatherIp + ":" + Common.fatherPort));
            logger.info("Sent back a father forwarding response to the file requested : " + fileName);
            try {
                LoggerFile.getInstance().info("Sent back a father forwaring response to the file requested : " + fileName);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

        // flush it out and we're done
        pwOut.flush();
    }

    /**
     * Performs a delete of a file based on a message from the child
     * @param commandLine The command as sent
     * @throws InterruptedException If putting the outgoing message to the father fails.
     */
    private void performDelete(String commandLine) throws InterruptedException {
        // parse the command
        String[] parts = commandLine.split(" ");
        // get the various parts
        String fileLocation = parts[1];
        String fileName = commandLine.substring(commandLine.indexOf(" ", commandLine.indexOf(" ")+1)+1); // it's the part from the second space and onward
        // see if there already is a file at that location (need to lock for mutual exclusion
        synchronized (Common.locker) {
            // if the file already exists here, remove the location
            if (Common.fileList.containsKey(fileName))
            {
                // get the location list
                FileEntry fileEntry = Common.fileList.get(fileName);
                LocationList locations = new LocationList(fileEntry.getFileLocation());
                // see if the location exists here to remove
                if (locations.containsLocation(fileLocation))
                {
                    // remove it
                    locations.removeLocation(fileLocation);
                    // update the entry
                    fileEntry.setFileLocation(locations.toString());
                    // see how many more locations are left
                    if (locations.locationCount() == 0)
                    {
                        // we need to update the father about the delete
                        Common.fatherMessages.put(Common.DELETE_COMMAND + " " + Common.ipRemoveSlash(Common.localIp.toString()) + ":" + Common.localPort + " " + fileName);
                        // need to remove it from the GUI too
                        Common.fileEntries.remove(fileEntry);
                        // remove it from the list of files we have
                        Common.fileList.remove(fileName);                    }
                }
            }
        }
    }

    /**
     * Performs the steps required to add the file to the local table when informed of it by a child
     * @param commandLine The command sent by the child
     * @throws InterruptedException If the queuing operation to tell the father fails
     */
    private void performAdd(String commandLine) throws InterruptedException {
        // parse the command
        String[] parts = commandLine.split(" ");
        // get the various parts
        String fileLocation = parts[1];
        String fileName = commandLine.substring(commandLine.indexOf(" ", commandLine.indexOf(" ")+1)+1); // it's the part from the second space and onward
        // see if there already is a file at that location (need to lock for mutual exclusion
        synchronized (Common.locker) {
            // if the file already exists here, add the location and we're done
            if (Common.fileList.containsKey(fileName))
            {
                // get the location list
                FileEntry fileEntry = Common.fileList.get(fileName);
                LocationList locations = new LocationList(fileEntry.getFileLocation());

                if (locations.addLocation(fileLocation)) {
                    // save it again
                    fileEntry.setFileLocation(locations.toString());
                    logger.info("Updated existing entry for file " + fileName + " with new location " + fileLocation);
                    try {
                        LoggerFile.getInstance().info("Updated existing entry for file " + fileName + " with new location " + fileLocation);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                } else {
                    logger.info("Failed to update existing entry for file " + fileName + " with location " + fileLocation + " must be a duplicate.");
                    try {
                        LoggerFile.getInstance().info("Failed to update existing entry for file " + fileName + " with location " + fileLocation + " must be a duplicate.");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            }
            else
            {
                // this is a new entry
                FileEntry fileEntry = new FileEntry();
                fileEntry.setFileName(fileName);
                fileEntry.setFileLocation(fileLocation);
                Common.fileList.put(fileName, fileEntry);
                Common.fileEntries.add(fileEntry); // add it to the list shown
                logger.info("Added an new entry for file " + fileName + " with new location " + fileLocation);
                try {
                    LoggerFile.getInstance().info("Added an new entry for file " + fileName + " with new location " + fileLocation);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                // we need to forward this to the father as well
                Common.fatherMessages.put(Common.ADD_COMMAND + " " + Common.ipRemoveSlash(Common.localIp.toString()) + ":" + Common.localPort + " " + fileName);
                logger.info("Informing father node of the new entry of file " + fileName);
                try {
                    LoggerFile.getInstance().info("Informing father node of the new entry of file " + fileName);
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }
    }
}
