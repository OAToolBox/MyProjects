from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse, IContextMenuInvocation
from javax import swing
from java.util import List, ArrayList
import json
import re
from collections import OrderedDict

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Convert Content Type")

        # Content-Types to be added to the context menu
        self.contentTypes = [
            "application/json", "text/plain", "application/x-www-form-urlencoded"
        ]

        # Register the context menu factory
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menuItems = ArrayList()
        submenu = swing.JMenu("Convert Content Type")
        
        for ct in self.contentTypes:
            menuItem = swing.JMenuItem(ct, actionPerformed=lambda e, ct=ct: self.convertContentType(invocation, ct))
            submenu.add(menuItem)

        menuItems.add(submenu)
        return menuItems

    def convertContentType(self, invocation, newContentType):
        http_traffic = invocation.getSelectedMessages()
        for traffic in http_traffic:
            if isinstance(traffic, IHttpRequestResponse):
                self.processHttpRequestResponse(traffic, newContentType)

    def processHttpRequestResponse(self, traffic, newContentType):
        request_info = self._helpers.analyzeRequest(traffic)
        headers = request_info.getHeaders()
        body = self._helpers.bytesToString(traffic.getRequest()[request_info.getBodyOffset():])

        # Modify the Content-Type header
        new_headers = []
        for header in headers:
            if header.lower().startswith("content-type:"):
                new_headers.append("Content-Type: " + newContentType)
            else:
                new_headers.append(header)

        # Convert the body based on the new Content-Type
        if newContentType == "application/json":
            try:
                # Convert URL-encoded body to JSON
                body_dict = self.parseUrlEncodedBody(body)
                body = json.dumps(body_dict, indent=4)
            except Exception as e:
                body = json.dumps({"data": body})
        elif newContentType == "text/plain":
            body = body  # No conversion needed for plain text
        elif newContentType == "application/x-www-form-urlencoded":
            try:
                body_dict = json.loads(body, object_pairs_hook=OrderedDict)
                body = "&".join(["{}={}".format(self._helpers.urlEncode(str(k)), self._helpers.urlEncode(str(v))) for k, v in body_dict.items()])
            except json.JSONDecodeError:
                body = "data=" + self._helpers.urlEncode(body)

        # Build the new request
        new_request = self._helpers.buildHttpMessage(new_headers, body.encode())

        # Send the modified request to the Repeater tab
        self._callbacks.sendToRepeater(traffic.getHttpService().getHost(), traffic.getHttpService().getPort(), 
                                       traffic.getHttpService().getProtocol() == "https", new_request, None)

    def parseUrlEncodedBody(self, body):
        """Parse URL-encoded body and return an OrderedDict to maintain parameter order."""
        body_dict = OrderedDict()
        for pair in body.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                body_dict[self._helpers.urlDecode(key)] = self._helpers.urlDecode(value)
            else:
                body_dict[self._helpers.urlDecode(pair)] = ''
        return body_dict
