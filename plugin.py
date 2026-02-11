from proxy.http.proxy import HttpProxyPlugin
from proxy.http.parser import HttpParser


class FirewallPlugin(HttpProxyPlugin):

    def handle_client_request(self, request: HttpParser):
        url = request.build_url()

        print(f"[REQUEST] {request.method} {url.decode(errors='ignore')}")

        return request
