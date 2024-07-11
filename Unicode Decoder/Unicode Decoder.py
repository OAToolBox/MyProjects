from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JScrollPane, JTextPane
from javax.swing.text import DefaultStyledDocument, StyleConstants, SimpleAttributeSet, StyleContext
import re
from java.awt import Color, Font  # Import the Color and Font classes from java.awt

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Unicode Decoder")
        
        # Register the custom message editor tab
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        # Create a new instance of the custom message editor tab
        return UnicodeDecoderTab(self, controller, editable)

class UnicodeDecoderTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        
        # Create a text pane to display the decoded text with syntax highlighting
        self._textPane = JTextPane()
        self._textPane.setFont(Font("Monospaced", Font.PLAIN, 20))  # Increased font size
        self._styledDoc = DefaultStyledDocument()
        self._textPane.setStyledDocument(self._styledDoc)
        self._scrollPane = JScrollPane(self._textPane)
        
        self._controller = controller
        self._currentMessage = None

    def getTabCaption(self):
        return "Unicode Decoder"

    def getUiComponent(self):
        return self._scrollPane

    def isEnabled(self, content, isRequest):
        # Enable this tab for all messages
        return content is not None

    def setMessage(self, content, isRequest):
        if content:
            analyzed_message = self._helpers.analyzeRequest(content) if isRequest else self._helpers.analyzeResponse(content)
            headers = analyzed_message.getHeaders()
            body = self._helpers.bytesToString(content[analyzed_message.getBodyOffset():])
            pretty_message = self.prettifyContent(headers, body)
            self.applySyntaxHighlighting(pretty_message)
        else:
            self._textPane.setText("")
        self._currentMessage = content

    def getMessage(self):
        return self._currentMessage

    def isModified(self):
        return False

    def getSelectedData(self):
        return None

    def decodeUnicode(self, text):
        # Decode Unicode escape sequences
        try:
            decoded_text = text.encode('latin1').decode('unicode-escape')
        except Exception as e:
            print("Error decoding text:", e)
            decoded_text = text
        return decoded_text

    def prettifyContent(self, headers, body):
        """Prettify the HTTP message for display."""
        headers_str = "\n".join(headers)
        body_str = self.decodeUnicode(body)
        return headers_str + "\n\n" + body_str

    def applySyntaxHighlighting(self, text):
        self._textPane.setText("")
        sc = StyleContext()
        default_style = sc.getStyle(StyleContext.DEFAULT_STYLE)

        header_name_style = sc.addStyle("HeaderName", default_style)
        StyleConstants.setForeground(header_name_style, Color(0, 0, 139))  # Dark blue for header names

        header_value_style = sc.addStyle("HeaderValue", default_style)
        StyleConstants.setForeground(header_value_style, Color(0, 0, 0))  # Black for header values

        key_style = sc.addStyle("Key", default_style)
        StyleConstants.setForeground(key_style, Color(255, 0, 0))  # Red for keys

        value_style = sc.addStyle("Value", default_style)
        StyleConstants.setForeground(value_style, Color(0, 128, 0))  # Green for values

        normal_style = sc.addStyle("Normal", default_style)
        StyleConstants.setForeground(normal_style, Color(0, 0, 0))  # Black for normal text

        if "\n\n" in text:
            headers, body = text.split("\n\n", 1)
        else:
            headers, body = text, ""

        lines = headers.split("\n")
        for line in lines:
            if ": " in line:
                header_name, header_value = line.split(": ", 1)
                self._styledDoc.insertString(self._styledDoc.getLength(), header_name + ": ", header_name_style)
                self._styledDoc.insertString(self._styledDoc.getLength(), header_value + "\n", header_value_style)
            else:
                self._styledDoc.insertString(self._styledDoc.getLength(), line + "\n", header_name_style)

        json_pattern = re.compile(r'(?P<brace>[\{\}\[\]])|(?P<key>"[^"]*"\s*:\s*)|(?P<string>"[^"]*")|(?P<number>\b\d+\b)')
        pos = 0
        for match in json_pattern.finditer(body):
            start, end = match.span()
            if pos < start:
                self._styledDoc.insertString(self._styledDoc.getLength(), body[pos:start], normal_style)
            if match.group("brace"):
                self._styledDoc.insertString(self._styledDoc.getLength(), match.group("brace"), normal_style)
            elif match.group("key"):
                self._styledDoc.insertString(self._styledDoc.getLength(), match.group("key"), key_style)
            elif match.group("string"):
                self._styledDoc.insertString(self._styledDoc.getLength(), match.group("string"), value_style)
            elif match.group("number"):
                self._styledDoc.insertString(self._styledDoc.getLength(), match.group("number"), normal_style)
            pos = end
        if pos < len(body):
            self._styledDoc.insertString(self._styledDoc.getLength(), body[pos:], normal_style)
