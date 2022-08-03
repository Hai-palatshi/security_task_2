package il.ac.kinneret.mjmay.hls.hlsjava.model;

import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

/**
 * Entries for the file in the files table and results table
 * @author Michael J. May
 * @version 1.0
 */
public class FileEntry {
    private StringProperty fileName;

    /**
     * Sets the file name for the entry
     * @param value The file name to set
     */
    public void setFileName(String value) { fileNameProperty().set(value); }

    /**
     * Gets the file name for the file entry
     * @return The file name
     */
    public String getFileName() { return fileNameProperty().get(); }
    public StringProperty fileNameProperty() {
        if (fileName == null) fileName = new SimpleStringProperty(this, "fileName");
        return fileName;
    }
    private StringProperty fileLocation;

    /**
     * Sets the file location
     * @param value The location to store
     */
    public void setFileLocation(String value) { fileLocationProperty().set(value); }

    /**
     * Gets the file location list
     * @return The list of file locations
     */
    public String getFileLocation() { return fileLocationProperty().get(); }
    public StringProperty fileLocationProperty() {
        if (fileLocation == null) fileLocation = new SimpleStringProperty(this, "fileLocation");
        return fileLocation;
    }

    private BooleanProperty isLocal;

    /**
     * Gets whether the file is stored locally
     * @param value Set true if stored locally.  Set false if not.
     */
    public void setIsLocal(Boolean value) { isLocalProperty().set(value); }

    /**
     * Gets whether the file is stored locally
     * @return True if stored locally. False otherwise
     */
    public Boolean getIsLocal() { return isLocalProperty().get(); }
    public BooleanProperty isLocalProperty() {
        if (isLocal == null) isLocal = new SimpleBooleanProperty(this, "isLocal");
        return isLocal;
    }
}
