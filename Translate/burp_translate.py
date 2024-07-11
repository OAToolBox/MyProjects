from burp import IBurpExtender, ITab
from javax.swing import JPanel, JTextArea, JButton, JScrollPane, JLabel, JTextField
from java.awt import BorderLayout, FlowLayout
import subprocess
import os

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Translate")

        # Create UI
        self.panel = JPanel(BorderLayout())
        self.inputPanel = JPanel(FlowLayout())
        self.outputPanel = JPanel(BorderLayout())

        self.sourceLangLabel = JLabel("Source Language:")
        self.sourceLangField = JTextField(5)
        self.targetLangLabel = JLabel("Target Language:")
        self.targetLangField = JTextField(5)
        self.inputTextArea = JTextArea(10, 50)
        self.translateButton = JButton("Translate", actionPerformed=self.translateText)
        self.outputTextArea = JTextArea(10, 50)
        self.outputScrollPane = JScrollPane(self.outputTextArea)

        self.inputPanel.add(self.sourceLangLabel)
        self.inputPanel.add(self.sourceLangField)
        self.inputPanel.add(self.targetLangLabel)
        self.inputPanel.add(self.targetLangField)
        self.inputPanel.add(self.translateButton)

        self.panel.add(self.inputPanel, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.inputTextArea), BorderLayout.CENTER)
        self.panel.add(self.outputScrollPane, BorderLayout.SOUTH)

        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Translate"

    def getUiComponent(self):
        return self.panel

    def translateText(self, event):
        source_lang = self.sourceLangField.text
        target_lang = self.targetLangField.text
        text = self.inputTextArea.text

        if not source_lang or not target_lang or not text:
            self.outputTextArea.text = "Please fill in all fields."
            return

        script_path = "translate_script.py"

        try:
            result = subprocess.check_output(
                ["python", script_path, source_lang, target_lang, text],
                stderr=subprocess.STDOUT
            )
            self.outputTextArea.text = result.decode('utf-8')
        except subprocess.CalledProcessError as e:
            self.outputTextArea.text = "Translation error: {}. Input was src='{}', dest='{}', text='{}'".format(e.output.decode('utf-8'), source_lang, target_lang, text)
        except FileNotFoundError:
            self.outputTextArea.text = "Error: Script file not found at {}".format(script_path)
        except Exception as e:
            self.outputTextArea.text = "Unexpected error: {}. Input was src='{}', dest='{}', text='{}'".format(str(e), source_lang, target_lang, text)
