from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpRequestResponse
from javax import swing
from java.awt import BorderLayout
import json, re

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request2Py")

        self.panel = swing.JPanel(BorderLayout())
        self.codeTextArea = swing.JTextArea()
        self.codeTextArea.setEditable(False)
        self.scrollPane = swing.JScrollPane(self.codeTextArea)
        self.panel.add(self.scrollPane)

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)

    def getTabCaption(self):
        return "Request2Py"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, contextMenuInvocation):
        menuItems = []
        menuItem = swing.JMenuItem("Generate Python Code", actionPerformed=lambda e: self.generateCode(contextMenuInvocation))
        menuItems.append(menuItem)
        return menuItems

    def generateCode(self, invocation):
        http_traffic = invocation.getSelectedMessages()
        for traffic in http_traffic:
            if isinstance(traffic, IHttpRequestResponse):
                self.processHttpRequestResponse(traffic)

    def processHttpRequestResponse(self, traffic):
        http_service = traffic.getHttpService()
        request_info = self._helpers.analyzeRequest(traffic)
        headers = request_info.getHeaders()
        body_bytes = traffic.getRequest()[request_info.getBodyOffset():]
        body = self._helpers.bytesToString(body_bytes)

        # Updated URL construction without f-strings
        url = "{}://{}:{}{}".format(http_service.getProtocol(), http_service.getHost(), http_service.getPort(), request_info.getUrl().getPath())
        method = headers[0].split(" ")[0]
        headers_dict = {header.split(": ")[0]: header.split(": ")[1] for header in headers[1:] if ": " in header}

        code = self.generatePythonCode(url, method, headers_dict, body)
        self.codeTextArea.append(code + "\n\n")

    def generatePythonCode(self, url, method, headers, body):
        # Convert headers to a string representation of a Python dictionary
        headers_formatted = json.dumps(headers, indent=4)
        
        # Construct the code using concatenation or str.format()
        code = "import requests\n\n"
        code += "url = '{}'\n".format(url)
        code += "headers = {}\n".format(headers_formatted)
        code += "response = requests.{}(url, headers=headers, data='''{}''')\n".format(method.lower(), body.replace("'", "\\'"))
        code += "print(response.text)\n"
        
        return code

