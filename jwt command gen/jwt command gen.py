from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpRequestResponse
from javax import swing
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
import re

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, ActionListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Command Gen")

        # Set up the UI components
        self.panel = swing.JPanel(BorderLayout())
        self.commandTextArea = swing.JTextArea()
        self.commandTextArea.setEditable(False)
        self.scrollPane = swing.JScrollPane(self.commandTextArea)
        self.panel.add(self.scrollPane, BorderLayout.CENTER)

        # Add manual JWT input fields
        self.manualInputPanel = swing.JPanel(FlowLayout())
        self.manualHeaderField = swing.JTextField(20)
        self.manualValueField = swing.JTextField(40)
        self.manualUrlField = swing.JTextField(40)
        self.generateManualButton = swing.JButton("Generate Manual JWT Command")
        self.generateManualButton.addActionListener(self)

        self.manualInputPanel.add(swing.JLabel("Header:"))
        self.manualInputPanel.add(self.manualHeaderField)
        self.manualInputPanel.add(swing.JLabel("Value:"))
        self.manualInputPanel.add(self.manualValueField)
        self.manualInputPanel.add(swing.JLabel("URL:"))
        self.manualInputPanel.add(self.manualUrlField)
        self.manualInputPanel.add(self.generateManualButton)
        
        self.panel.add(self.manualInputPanel, BorderLayout.SOUTH)

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def getTabCaption(self):
        return "JWT Command Gen"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, contextMenuInvocation):
        menuItems = []
        menuItem = swing.JMenuItem("Generate JWT Command", actionPerformed=lambda e: self.generateCommand(contextMenuInvocation))
        menuItems.append(menuItem)
        return menuItems

    def generateCommand(self, invocation):
        http_traffic = invocation.getSelectedMessages()
        for traffic in http_traffic:
            if isinstance(traffic, IHttpRequestResponse):
                self.processHttpRequestResponse(traffic)

    def processHttpRequestResponse(self, traffic):
        http_service = traffic.getHttpService()
        request_info = self._helpers.analyzeRequest(traffic)
        headers = request_info.getHeaders()
        
        # Find the JWT header
        jwt_header = None
        jwt_value = None
        for header in headers:
            if re.search("authorization", header, re.IGNORECASE):
                jwt_header, jwt_value = header.split(": ", 1)
                break
        
        # Construct the URL
        protocol = http_service.getProtocol()
        host = http_service.getHost()
        port = http_service.getPort()
        url_path = request_info.getUrl().getPath()
        url_query = request_info.getUrl().getQuery()
        if url_query:
            full_url = "{}://{}:{}{}?{}".format(protocol, host, port, url_path, url_query)
        else:
            full_url = "{}://{}:{}{}".format(protocol, host, port, url_path)

        # Populate manual input fields with the extracted values
        self.manualUrlField.setText(full_url)
        if jwt_header and jwt_value:
            self.manualHeaderField.setText(jwt_header)
            self.manualValueField.setText(jwt_value)
            # Generate the command
            command = 'python3 jwt_tool.py -M at -t "{}" -rh "{}: {}" -np'.format(full_url, jwt_header, jwt_value)
            self.commandTextArea.append(command + "\n\n")
        else:
            self.commandTextArea.append("JWT header not found in the selected request. Please enter manually.\n\n")

    def actionPerformed(self, event):
        if event.getSource() == self.generateManualButton:
            self.generateManualCommand()

    def generateManualCommand(self):
        header = self.manualHeaderField.getText()
        value = self.manualValueField.getText()
        url = self.manualUrlField.getText()
        if header and value and url:
            # Use the manual input to generate the command
            command = 'python3 jwt_tool.py -M at -t "{}" -rh "{}: {}" -np'.format(url, header, value)
            self.commandTextArea.append(command + "\n\n")
        else:
            self.commandTextArea.append("Please enter header, value, and URL.\n\n")

