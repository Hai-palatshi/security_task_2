package il.ac.kinneret.mjmay.hls.hlsjava;

import il.ac.kinneret.mjmay.hls.hlsjava.model.Common;
import il.ac.kinneret.mjmay.hls.hlsjava.model.LoggerFile;
import javafx.application.Application;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;

import java.io.IOException;

/**
 * Represents the top level of the application, not much to see here.
 */
public class HLSApplication extends Application {

    public static Stage theStage;

    /**
     * Starts the app
     * @param stage The stage with the main screen on it
     * @throws IOException If something goes wrong with the setup
     */
    @Override
    public void start(Stage stage) throws IOException {
        LoggerFile.getInstance().info("Node is up!");
        FXMLLoader fxmlLoader = new FXMLLoader(HLSApplication.class.getResource("hls.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 700, 600);

        theStage = stage;

        stage.setTitle("Hierarchical Local Service Tool");
        stage.getIcons().add(new Image("file:./hls.png"));
        stage.setScene(scene);
        stage.show();

        stage.setOnHiding(windowEvent -> {
            if (Common.serverSocket != null) {
                try {
                    Common.serverSocket.close();
                } catch (Exception ex) {
                    // not much to do here
                }
            }
        });
    }

    /**
     * Main to start the app
     * @param args Ignored
     */
    public static void main(String[] args) {
        launch();
    }
}