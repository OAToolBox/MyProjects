
# Burp Suite Jython Extensions

Welcome to the Burp Suite Jython Extensions repository! This repository contains several custom extensions I developed for Burp Suite, all written in Jython. These extensions enhance Burp Suite's functionality, making it more powerful and user-friendly for your security testing needs.

## Getting Started

To use these extensions in Burp Suite, follow these steps:

1. **Install global dependencies:**
   Run the following command to install global dependencies:
   ```
   pip install -r requirements.txt
   ```
   **Alternatively You can install extension-specific dependencies:**
   Each extension folder contains its own `requirements.txt` file. Navigate to the desired extension folder and install its dependencies:
   ```
   pip install -r extension-folder-name/requirements.txt
   ```

3. **Add extensions to Burp Suite:**
   - Open Burp Suite.
   - Go to the "Extensions" tab.
   - Click on the "Installed" sub-tab.
   - Click "Add" and choose the appropriate .py file from the folder of the extension you want to add.
	 In some cases there will be an extension with more than one file. In that case you should add the file with the word "main" in its name and check that the other files related to it exist in the same folder.

## Extensions

### Content Type Converter
Convert the content type of a request. Right-click on the request, choose this extension, and select the target content type. The extension updates both the request header and body, creating a new tab in the Repeater with the converted request.

### Request2Python
Convert HTTP requests to Python code. Right-click on the request, select this extension, and the Python code representation of the request will be displayed in a new tab within the extension interface.

### Translate
This extension adds a tab where you can input text to translate from one language to another. Specify the source and target languages, and the extension will provide the translated text.

### Unicode Decoder
Add a new tab to the request/response viewer to display any Unicode-encoded characters in a human-readable format. It appears alongside existing tabs like "Pretty" and "Raw."

### Translated & Decoded
This extension adds a new tab to the request/response viewer. It collects encoded non-English characters and translates the content into English.

### JWT Command Generator
Generate `jwt_tool` commands directly from your requests. Right-click on a request, select this extension, and it will send the JWT and URL to the extension tab as inputs. The extension then generates a `jwt_tool` command, ready to be copied and used in the command line for testing security vulnerabilities. It also have a manual option for inputs.

---

Enhance your Burp Suite experience with these handy extensions. Contributions, issues, and suggestions are welcome! Happy testing!
