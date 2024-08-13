from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JScrollPane, JTextPane
from javax.swing.text import DefaultStyledDocument, StyleConstants, StyleContext
import re
from java.awt import Color, Font
import subprocess
import array  # Import the array module

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Translated & Decoded")
        
        # Register the custom message editor tab
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        # Create a new instance of the custom message editor tab
        return TranslatedDecodedTab(self, controller, editable)

class TranslatedDecodedTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable
        
        # Create a text pane to display the decoded and translated text with syntax highlighting
        self._textPane = JTextPane()
        self._textPane.setFont(Font("Monospaced", Font.PLAIN, 20))  # Increased font size
        self._styledDoc = DefaultStyledDocument()
        self._textPane.setStyledDocument(self._styledDoc)
        self._scrollPane = JScrollPane(self._textPane)
        
        self._controller = controller
        self._currentMessage = None

    def getTabCaption(self):
        return "Translated & Decoded"

    def getUiComponent(self):
        return self._scrollPane

    def isEnabled(self, content, isRequest):
        # Enable this tab for all messages
        return content is not None

    def setMessage(self, content, isRequest):
        if content:
            analyzed_message = self._helpers.analyzeRequest(content) if isRequest else self._helpers.analyzeResponse(content)
            headers = analyzed_message.getHeaders()
            body = content[analyzed_message.getBodyOffset():]
            decoded_body = self.decodeText(body)
            
            # Translate only the non-English parts of the decoded body
            translated_body = self.translateText(decoded_body, "en")
            
            pretty_message = self.prettifyContent(headers, translated_body)
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

    def decodeText(self, byte_array):
        # Convert array to bytes
        if isinstance(byte_array, array.array):
            byte_array = byte_array.tostring()
        
        # Try common encodings
        encodings = ['utf-8', 'iso-8859-1', 'shift_jis', 'euc-jp', 'gb2312']
        for enc in encodings:
            try:
                return byte_array.decode(enc)
            except (UnicodeDecodeError, AttributeError):
                continue
        
        # Fall back to replacing errors if all else fails
        return byte_array.decode('utf-8', errors='replace')

    def translateText(self, text, target_lang="en"):
        script_path = "translate_script.py"
        source_lang = "auto"

        try:
            # Regex to find non-English characters
            non_english_pattern = re.compile(r'[^\x00-\x7F]+')
            
            # Find all non-English segments
            non_english_segments = non_english_pattern.findall(text)
            
            if not non_english_segments:
                return text  # No translation needed if no non-English text
            
            # Combine all non-English segments into one string, separated by a newline
            combined_segments = "\n".join(non_english_segments)
            encoded_segments = combined_segments.encode('utf-8')
            
            print("Translating combined segments: %s..." % encoded_segments[:100])
            
            # Translate the combined non-English segments
            result = subprocess.check_output(
                ["python", script_path, source_lang, target_lang, encoded_segments],
                stderr=subprocess.STDOUT
            )
            
            # Split the translated result back into individual segments
            translated_segments = result.decode('utf-8').split("\n")
            
            # Replace non-English segments with their translations, ensuring all are replaced
            translated_text = text
            for original, translated in zip(non_english_segments, translated_segments):
                translated_text = translated_text.replace(original, translated, 1)
            
            print("Final translated text:", translated_text)
            return translated_text
        
        except subprocess.CalledProcessError as e:
            error_message = e.output.decode('utf-8')
            print("Translation error:", error_message)
            return "Translation error: %s" % error_message
        
        except FileNotFoundError:
            return "Error: Script file not found at %s" % script_path
        
        except Exception as e:
            return "Unexpected error: %s. Input was src='%s', dest='%s', text='%s...'" % (
                str(e), source_lang, target_lang, text[:100])




    def prettifyContent(self, headers, body):
        """Prettify the HTTP message for display."""
        headers_str = "\n".join(headers)
        return headers_str + "\n\n" + body

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
