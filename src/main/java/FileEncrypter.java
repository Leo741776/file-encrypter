import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class FileEncrypter extends Application {

    @Override
    public void start(Stage stage) {
        stage.setTitle("DES File Cipher");

        ToggleGroup modeGroup = new ToggleGroup();
        RadioButton encryptButton = new RadioButton("Encrypt");
        RadioButton decryptButton = new RadioButton("Decrypt");
        encryptButton.setToggleGroup(modeGroup);
        decryptButton.setToggleGroup(modeGroup);
        encryptButton.setSelected(true);

        TextField inputField = new TextField();
        inputField.setPromptText("Select a file...");
        // Stretch the field so it fills whatever width the HBox doesn't reserve for the button
        HBox.setHgrow(inputField, Priority.ALWAYS);

        Button browseButton = new Button("Browse");
        browseButton.setOnAction(e -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Select File");
            java.io.File file = chooser.showOpenDialog(stage);
            if (file != null) {
                inputField.setText(file.getAbsolutePath());
            }
        });

        HBox fileBox = new HBox(10, inputField, browseButton);

        TextField keyField = new TextField();
        keyField.setPromptText("16-character hexadecimal key");
        // Same as inputField â€” keep the key field wide
        HBox.setHgrow(keyField, Priority.ALWAYS);

        Button generateKeyButton = new Button("Generate Random Key");
        generateKeyButton.setOnAction(e -> keyField.setText(KeyDatabase.generateRandomHexKey()));

        HBox keyBox = new HBox(10, keyField, generateKeyButton);

        decryptButton.selectedProperty().addListener((obs, wasSelected, isSelected) ->
                generateKeyButton.setVisible(!isSelected));

        TextArea outputArea = new TextArea();
        outputArea.setEditable(false);
        outputArea.setPrefRowCount(3);

        Button runButton = new Button("Run");

        HBox runRow = new HBox(runButton);
        runRow.setAlignment(javafx.geometry.Pos.CENTER_RIGHT);

        VBox root = new VBox(10,
                new Label("Mode"), new HBox(10, encryptButton, decryptButton),
                new Label("File"), fileBox,
                new Label("Key"), keyBox,
                new Label("Message"), outputArea,
                runRow
        );
        root.setPadding(new Insets(15));

        runButton.setOnAction(e -> {
            String mode = encryptButton.isSelected() ? "encrypt" : "decrypt";
            String input = inputField.getText().trim();
            String key = keyField.getText().trim();

            java.io.File inputFile = new java.io.File(input);
            if (!inputFile.isFile()) {
                outputArea.setText("Error: Input file does not exist.");
                return;
            }
            if (key.length() != 16 || !key.matches("[0-9a-fA-F]+")) {
                outputArea.setText("Error: Key must be exactly 16 hex characters.");
                return;
            }
            if (mode.equals("decrypt")) {
                long fileSize = inputFile.length();
                // The first 8 bytes of every encrypted file are the IV, so valid sizes are 8 + (n * 8)
                if (fileSize < 8 || (fileSize - 8) % 8 != 0) {
                    outputArea.setText("Error: File does not appear to be a valid encrypted file.");
                    return;
                }
            }

            FileChooser saveChooser = new FileChooser();
            saveChooser.setTitle("Save Output File");
            saveChooser.setInitialDirectory(inputFile.getParentFile());

            // Strip .enc when decrypting so the save dialog pre-fills the original filename
            String suggestedName;
            if (mode.equals("encrypt")) {
                suggestedName = inputFile.getName() + ".enc";
            } else if (inputFile.getName().endsWith(".enc")) {
                suggestedName = inputFile.getName().substring(0, inputFile.getName().length() - 4);
            } else {
                suggestedName = inputFile.getName() + ".dec";
            }
            saveChooser.setInitialFileName(suggestedName);

            java.io.File outputFile = saveChooser.showSaveDialog(stage);
            if (outputFile == null) return;

            try {
                DESFileCipher.process(mode, input, key, outputFile.getAbsolutePath());
                outputArea.setText("File successfully " + (mode.equals("encrypt") ? "encrypted" : "decrypted")
                        + "!\nSaved to: " + outputFile.getAbsolutePath());
            } catch (Exception exception) {
                outputArea.setText("Error: " + exception.getMessage());
                exception.printStackTrace();
            }
        });

        stage.setScene(new Scene(root));
        stage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}