package il.ac.kinneret.mjmay.hls.hlsjava;

import il.ac.kinneret.mjmay.hls.hlsjava.model.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.Event;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.paint.Paint;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;

import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

import static il.ac.kinneret.mjmay.hls.hlsjava.model.Common.*;

/**
 * Handles all of the GUI interactions from the user.  Tries to not do that much aside from that.
 * @author Michael J. May
 * @version 1.0
 */
public class HLSController implements Initializable {
    public TextField tfMyIp;
    public Button bAuto;
    public TextField tfMyPort;
    public Button bStart;
    public CheckBox cbRoot;
    public TextField tfFileFind;
    public ListView lvResults;
    public Button bRetrieve;
    public TextField tfFileAdd;
    public Button bAddBrowse;
    public Button bDeleteBrowse;
    public TextField tfFileDelete;
    public TableView tvFileInfo;
    public TextField tfFatherIp;
    public TextField tfFatherPort;
    /**
     * Incoming listening thread
     */
    Listener listener;
    /**
     * Outgoing messages thread
     */
    OutgoingTalker outgoingTalker;
    /**
     * Used for letting the user select a file to add or remove
     */
    FileChooser fileChooser;
    /**
     * Used for letting the user select a directory to store a retrieved file in.
     */
    private DirectoryChooser directoryChooser;

    /**
     * For logging the messages from the class
     */
    Logger logger;

    /**
     * Automatically fills in the IP address for the node using the first non-localhost IP address found
     * @param event Ignored
     */
    public void automaticIP (Event event)  {

        tfMyIp.setText("");
        try {
            // get the local IP addresses from the network interface listing
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                // see if it has an IPv4 address
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    // go over the addresses and add them
                    InetAddress add = addresses.nextElement();
                    if (!add.isLoopbackAddress() && add instanceof Inet4Address) {
                        tfMyIp.setText(add.toString());
                        break;
                    }
                }

                if (!tfMyIp.getText().equals("")) {
                    break;
                }
            }
        } catch (Exception ex)
        {
            tfMyIp.setText("/127.0.0.1");
        }
    }

    /**
     * Event for handling when the root check box is changed
     * @param event Ignored
     */
    public void rootChanged (Event event) {
        Common.isRoot = cbRoot.isSelected();
        // if it's now a root, disable the father IP and father port
        if (cbRoot.isSelected())
        {
            tfFatherIp.setDisable(true);
            tfFatherPort.setDisable(true);
        }
        else
        {
            tfFatherPort.setDisable(false);
            tfFatherIp.setDisable(false);
        }
    }

    /**
     * Event for handling when the local IP field is changed.  Attempts to instantly parse it
     * @param event  Ignored
     */
    public void localIPChanged (Event event) {
        try {
            Common.localIp = Inet4Address.getByName(tfMyIp.getText());
        } catch (Exception ex)
        {
            // invalid IP address
        }
    }

    /**
     * Event for handling when the local port field is changed.  Attempts to instantly parse it
     * @param event  Ignored
     */
    public void localPortChanged (Event event) {
        try {
            Common.localPort = Integer.parseInt(tfMyPort.getText());
        } catch (Exception exception)
        {
            // something's wrong with the number provided
        }
    }

    /**
     * Event for handling when the father IP field is changed.  Attempts to instantly parse it
     * @param event  Ignored
     */
    public void fatherIPChanged (Event event) {
        try {
            Common.fatherIp = Inet4Address.getByName(tfFatherIp.getText());
        } catch (Exception ex)
        {
            // invalid IP address
        }
    }

    /**
     * Event for handling when the father port field is changed.  Attempts to instantly parse it
     * @param event  Ignored
     */
    public void fatherPortChanged (Event event) {
        try {
            Common.fatherPort = Integer.parseInt(tfFatherPort.getText());
        } catch (Exception ex)
        {
            // something's wrong with the number provided
        }
    }

    /**
     * Shows the file browse window when looking for a file to add or remove.
     * @param event Used to identify which button was pressed
     */
    public void browseFile (Event event) {
        // show the file chooser
        fileChooser.setTitle("Choose a file");
        File chosenFile = fileChooser.showOpenDialog(HLSApplication.theStage);

        // if no file is chosen, then return
        if (chosenFile == null)
        {
            return;
        }

        if (event.getSource() == bAddBrowse)
        {
            // put the chosen file in the add text field
            tfFileAdd.setText(chosenFile.toString());
        }
        else if (event.getSource() == bDeleteBrowse)
        {
            tfFileDelete.setText(chosenFile.toString());
        }
    }

    /**
     * Starts or stops the node from listening.
     * @param event Ignored
     */
    public void startStopListening (Event event)
    {
        // if not listening, start listening
        if (!Common.isListening)
        {
            try {
                Common.localIp = InetAddress.getByName(Common.ipRemoveSlash(tfMyIp.getText()));
                Common.localPort = Integer.parseInt(tfMyPort.getText());
                if (!cbRoot.isSelected()) { // get the father info if we're not the root
                    Common.fatherIp = InetAddress.getByName(Common.ipRemoveSlash(tfFatherIp.getText()));
                    Common.fatherPort = Integer.parseInt(tfFatherPort.getText());
                    // create the talker for the father
                    outgoingTalker = new OutgoingTalker();
                    outgoingTalker.start();
                    logger.info("Not the root.  Father is: " + Common.fatherIp.toString() + ":" + Common.fatherPort);
                    LoggerFile.getInstance().info("Not the root.  Father is: " + Common.fatherIp.toString() + ":" + Common.fatherPort);

                }
                Common.serverSocket = new ServerSocket(Integer.parseInt(tfMyPort.getText()), 50, InetAddress.getByName(Common.ipRemoveSlash(tfMyIp.getText())));
                listener = new Listener(Common.serverSocket);
                listener.start();
                Common.isListening = true;
                bStart.setTextFill(Paint.valueOf("FA8072"));
                bStart.setText("Stop");
                logger.info("Started listening on IP " + Common.localIp.toString() + ":" + Common.localPort);
                LoggerFile.getInstance().info("Started listening on IP " + Common.localIp.toString() + ":" + Common.localPort);

            }
            catch (NumberFormatException | IOException | IndexOutOfBoundsException ex)
            {
                System.err.println("Error parsing IP address or port.  Check inputs");
                return;
            }
        }
        else {
            // stop the listener
            listener.interrupt();
            if (!cbRoot.isSelected() && outgoingTalker != null){
                // cancel the outgoing talker if there is one
                outgoingTalker.interrupt();
            }
            try {
                Common.serverSocket.close();
            } catch (IOException iox)
            {
                System.err.println("Error stopping to listen: " + iox.getLocalizedMessage());
            }
            listener = null;
            outgoingTalker = null;
            bStart.setText("Start");
            bStart.setTextFill(Paint.valueOf("0dbf74"));
            Common.isListening = false;
        }
    }

    /**
     * Adds a file to the node's local file storage list. Notifies the father if necessary
     * @param event Ignored
     */
    public void addFile(Event event) {
        // check if the file is already found in the table
        String addFileName = tfFileAdd.getText().substring(tfFileAdd.getText().lastIndexOf(File.separator)+1);
        FileEntry newEntry;
        synchronized (locker) {
            if (!Common.fileList.containsKey(addFileName)) {
                // create a new entry for the file
                newEntry = new FileEntry();
                newEntry.setFileName(addFileName);
                newEntry.setFileLocation(tfFileAdd.getText().substring(0, tfFileAdd.getText().lastIndexOf(File.separator)));
                newEntry.setIsLocal(true);
                fileEntries.add(newEntry);
                Common.fileList.put(addFileName, newEntry);
                // send a notice to the father as needed
                ClientActions.localAdd(newEntry.getFileName());
                // create encrypted version of the file
                try {
                    Encryption.encryptFile(tfFileAdd.getText(), tfFileAdd.getText()+".enc");
                } catch (NoSuchPaddingException | NoSuchAlgorithmException | IOException | InvalidKeyException | InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                }

                logger.info("Added a new entry for file " + addFileName + " to the local file list at " + newEntry.getFileName());
                try {
                    LoggerFile.getInstance().info("Added a new entry for file " + addFileName + " to the local file list at " + newEntry.getFileName());
                } catch (IOException e) {
                    e.printStackTrace();
                }

            } else {
                // get the existing entry
                newEntry = Common.fileList.get(addFileName);
                LocationList locations = new LocationList(newEntry.getFileLocation());
                if (locations.addLocation(tfFileAdd.getText().substring(0, tfFileAdd.getText().lastIndexOf(File.separator)))) {
                    newEntry.setFileLocation(locations.toString());
                    newEntry.setIsLocal(true);
                    logger.info("Updated an existing entry for file " + addFileName + " in the local file list.");
                    try {
                        LoggerFile.getInstance().info("Updated an existing entry for file " + addFileName + " in the local file list.");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                } else {
                    logger.info("Failed to update an existing entry for file " + addFileName + " in the local file list.  It must be a duplicate.");
                    try {
                        LoggerFile.getInstance().info("Failed to update an existing entry for file " + addFileName + " in the local file list.  It must be a duplicate.");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            }
        }
    }

    /**
     * Resends all of the add messages to the father for the files in the node
     * @param event Ignored
     */
    public void resendAllAddFile(Event event) {
        // go over the list of files in the file table and send an add message to the father for each of them once
        for (FileEntry entry : fileEntries)
        {
            ClientActions.localAdd(entry.getFileName());
        }
    }

    /**
     * Deletes a file from the node's local file storage list. Notifies the father if necessary
     * @param event Ignored
     */
    public void deleteFile (Event event)
    {
        // check if the file is in the table
        String deleteFileName = tfFileDelete.getText().substring(tfFileDelete.getText().lastIndexOf(File.separator)+1);
        synchronized (locker) {
            if (Common.fileList.containsKey(deleteFileName)) {
                // it exists, remove the location from the list
                FileEntry fileEntry = Common.fileList.get(deleteFileName);
                LocationList locationList = new LocationList(fileEntry.getFileLocation());
                // remove the local address by filtering out all of the local addresses from the list
                fileEntry.setFileLocation(locationList.toNonLocalString());

                // see if there are any locations left in the entry
                if (locationList.toNonLocalString().length() == 0) {
                    // there are no more locations, so just remove it entirely
                    fileEntries.remove(fileEntry);
                    // remove it from the list
                    Common.fileList.remove(deleteFileName);

                    // we need to notify the parent if there is one about this since it's the last copy in this branch
                    ClientActions.localRemove(deleteFileName);
                }
            }
        }
    }

    /**
     * Search for a file using the window.  If the file is found locally, only the local directory is shown. if the file
     * if found in any of the locations in the node's subtree, all subtree locations are shown.  if the file is not
     * found in the node's subtree, only a single non-subtree location is shown.
     * @param event ignored.
     */
    public void searchFile (Event event) {
        String searchFileName = tfFileFind.getText();
        // if it's empty, just return
        if (searchFileName.length() == 0) return;

        // clear the results list
        lvResults.setItems(null);
        ArrayList<String> results = new ArrayList<>();

        // it's not empty, so see if it's local or in the children
        if (fileList.containsKey(searchFileName))
        {
            // see if it's local
            FileEntry localFileEntry = fileList.get(searchFileName);
            LocationList localLocationList = new LocationList(localFileEntry.getFileLocation());
            if (localFileEntry.getIsLocal())
            {
                results.add(localLocationList.getLocalLocation());
            }
            else
            {
                // check the children
                String[] childrenLocations = localLocationList.toNonLocalString().split(";");
                for (String childLocation : childrenLocations)
                {
                    // check the child
                    try {
                        ClientActions.iterateSearchSearch(InetAddress.getByName(childLocation.split(":")[0]), Integer.parseInt(childLocation.split(":")[1]),
                                searchFileName, results);
                    } catch (Exception ex)
                    {
                        // can't ask this child
                        logger.severe("Error contacting child for file search: " + childLocation + ": " + ex.getMessage());
                    }
                }
            }
        }
        else if (!cbRoot.isSelected()){
            // it's not in the file list, so ask the father if we're not the root
            ClientActions.searchFather(searchFileName, results);
        }

        // put the results in the list
        ObservableList<String> locationResults = FXCollections.observableArrayList(results);
        lvResults.setItems(locationResults);
    }

    /**
     * Performs the actions to retrieve a file from the remote node that has the it.  Only works if a file is selected
     * from the list view with the results
     * @param event Ignored
     */
    public void retrieveFile (Event event) {
        // see whether there are results and one is selected
        if (lvResults.getItems().size() > 0 && lvResults.getSelectionModel().getSelectedItems().size() > 0)
        {
            // get the selected entry
            String location = lvResults.getSelectionModel().getSelectedItem().toString();
            // see if this is local
            try {
                InetAddress address = InetAddress.getByName(location.split(":")[0]);
                int port = Integer.parseInt(location.split(":")[1]);

                // ask where to store it first
                File destinationFile = directoryChooser.showDialog(HLSApplication.theStage);
                if (destinationFile != null && destinationFile.isDirectory()) {
                    // open it from the remote site
                    if(ClientActions.retrieveFile(address, port, tfFileFind.getText(), destinationFile))
                    {
                        // show the file location
                        Runtime.getRuntime().exec("explorer /select," + destinationFile.toString() + File.separator + tfFileFind.getText());
                    } else {
                        // something failed hre
                        logger.severe("Something went wrong retrieving the file, it didn't arrive.");
                        LoggerFile.getInstance().info("Something went wrong retrieving the file, it didn't arrive.");

                        return;
                    };
                }
            }
            catch (Exception exception)
            {
                // clearly this is local
                try {
                    Runtime.getRuntime().exec("explorer /select," + location + File.separator + tfFileFind.getText());
                } catch (Exception e)
                {
                    logger.severe("Can't open the local location of the file: " + location + tfFileFind.getText() + ": " + e.getMessage());
                    try {
                        LoggerFile.getInstance().info("Can't open the local location of the file: " + location + tfFileFind.getText() + ": " + e.getMessage());
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }

                    return;
                }
            }
        }
    }

    /**
     * Initializes the GUI with the necessary object member variables and setup
     * @param url Ignored
     * @param resourceBundle Ignored
     */
    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {

        automaticIP(null);
        // prepare the file chooser dialog
        fileChooser = new FileChooser();
        directoryChooser = new DirectoryChooser();
        // initialize the file list
        Common.fileList = new HashMap<>();
        logger = Logger.getLogger(HLSController.class.getName());
        lvResults.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);

        // the file info
        fileEntries = FXCollections.observableArrayList();
        tvFileInfo.setItems(fileEntries);
        FileEntry entry = new FileEntry();
        TableColumn<String, String> fileNameColumn = (TableColumn<String, String>) tvFileInfo.getColumns().get(0);
        fileNameColumn.setCellValueFactory(new PropertyValueFactory<>(entry.fileNameProperty().getName()));
        TableColumn<String, String> fileLocationColumn = (TableColumn<String, String>) tvFileInfo.getColumns().get(1);
        fileLocationColumn.setCellValueFactory(new PropertyValueFactory<>(entry.fileLocationProperty().getName()));
        TableColumn<Boolean, String> fileLocalColumn = (TableColumn<Boolean, String>) tvFileInfo.getColumns().get(2);
        fileLocalColumn.setCellValueFactory(new PropertyValueFactory<>(entry.isLocalProperty().getName()));
    }
}