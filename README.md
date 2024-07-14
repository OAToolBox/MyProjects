
# Burp Suite Jython Extensions

Welcome to the Burp Suite Jython Extensions repository! This repository contains several custom extensions I developed for Burp Suite, all written in Jython. These extensions enhance Burp Suite's functionality, making it more powerful and user-friendly for your security testing needs.

## Getting Started

To use these extensions in Burp Suite, follow these steps:

1. **Clone the repository:**
   \`\`\`bash
   git clone https://github.com/yourusername/burp-suite-jython-extensions.git
   cd burp-suite-jython-extensions
   \`\`\`

2. **Install global dependencies:**
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

3. **Install extension-specific dependencies:**
   Each extension folder contains its own \`requirements.txt\` file. Navigate to the desired extension folder and install its dependencies:
   \`\`\`bash
   cd extension-folder-name
   pip install -r requirements.txt
   cd ..
   \`\`\`

4. **Add extensions to Burp Suite:**
   - Open Burp Suite.
   - Go to the "Extender" tab.
   - Click on the "Extensions" sub-tab.
   - Click "Add" and choose the appropriate .py file from the folder of the extension you want to add.

## Extensions

### Content Type Converter
This extension allows you to convert the content type of a request easily. Simply right-click on the request, choose this extension, and select the target content type. The extension updates both the request header and body, creating a new tab in the Repeater with the converted request.

### Request2Python
Convert HTTP requests to Python code with this extension. Right-click on the request, select this extension, and the Python code representation of the request will be displayed in a new tab within the extension interface.

### Translate
This extension adds a tab where you can input text to translate from one language to another. Specify the source and target languages, and the extension will provide the translated text.

### Unicode Decoder
This extension adds a new tab to the request/response viewer, displaying any Unicode-encoded characters in a human-readable format. It appears alongside existing tabs like "Pretty" and "Raw."

### Translated & Decoded
Similar to the Unicode Decoder, this extension adds a new tab to the request/response viewer. It decodes Unicode characters and translates the content to English, providing a clear view of the text in a single tab.

### JWT Command Generator
Generate \`jwt_tool\` commands directly from your requests. Right-click on a request, select this extension, and it will extract the JWT and URL. The extension then generates a \`jwt_tool\` command, ready to be copied and used in the command line for testing security vulnerabilities.

---

Enhance your Burp Suite experience with these handy extensions. Contributions, issues, and suggestions are welcome! Happy testing!
