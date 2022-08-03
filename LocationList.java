package il.ac.kinneret.mjmay.hls.hlsjava.model;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.stream.IntStream;

/**
 * Represents a list of locations for a file entry.
 * @author Michael J. May
 * @version 1.0
 */
public class LocationList {

    ArrayList<String> locations;

    /**
     * Creates a new location list object
     * @param locs A semicolon delimited list of locations
     */
    public LocationList(String locs) {
        locations = new ArrayList<>();
        String[] locParts = locs.split(";");
        IntStream.range(0, locParts.length).forEach(i -> locations.add(locParts[i]));
    }

    /**
     * Adds a new location to the list of locations.  If the location already exists, it is ignored
     * @param l The location to add
     * @return True if the location is added.  False otherwise (if it's a duplicate).
     */
    public boolean addLocation(String l)
    {
        if (!locations.contains(l))
        {
            locations.add(l);
            return true;
        }
        else
        {
            return false;
        }
    }

    /**
     * Removes a location from the location list
     * @param l The location to remove
     * @return True if the location was removed.  False otherwise
     */
    public boolean removeLocation (String l)
    {
        return locations.remove(l);
    }

    /**
     * Checks whether a location is found in the list
     * @param l The location to look for
     * @return True if the location is found.  False otherwise.
     */
    public boolean containsLocation(String l) {
        return locations.contains(l);
    }

    /**
     * Gives the total number of locations in the list
     * @return The number of locations in the list
     */
    public int locationCount()
    {
        return locations.size();
    }

    /**
     * Gets the local part of the location list (if there is one).
     * @return The local address in the list of locations.  If there is no local location, returns the empty string
     */
    public String getLocalLocation()
    {
        // find the part of the location list that's local (if there is one)
        String local = "";
        for (String s : locations) {
            try {
                // see if this is an IP address
                InetAddress add = InetAddress.getByName(s.substring(0, s.indexOf(":")));
            } catch (Exception ex)
            {
                // this must be the one
                local = s;
            }
        }
        return local;
    }

    /**
     * Returns all of the locations in the list except for the ones that are local
     * @return String of all locations (; delimited) except for the local ones
     */
    public String toNonLocalString()
    {
        StringBuilder sb = new StringBuilder();
        for (String s : locations) {
            try {
                // see if this is an internet address, if not it's a local address
                InetAddress add = InetAddress.getByName(s.substring(0, s.indexOf(":")));
                sb.append(s + ";");
            } catch (Exception ex)
            {
                // this is not an IP address, so skip it
            }
        }
        if (sb.length() > 0) {
            return sb.substring(0, sb.length() - 1); // remove the trailing ;
        } else
        {
            return ""; // nothing here
        }
    }

    /**
     * Converts the locations to a semicolon (;) delimited list
     * @return The locations in a ; delimited string
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (String s : locations)
        {
            sb.append(s + ";");
        }
        if (sb.length() > 0) {
            return sb.substring(0, sb.length() - 1); // remove the trailing ;
        }
        else
        {
            return "";
        }
    }
}
