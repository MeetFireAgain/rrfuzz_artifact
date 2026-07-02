import abc
import requests
import socket
import logging
from typing import Any, Dict, Optional

class BaseProtocolAdapter(abc.ABC):
    """
    Abstract base class for interacting with different protocols (HTTP, TCP, etc.)
    """
    def __init__(self, target_ip: str, target_port: int, timeout: int = 10):
        self.target_ip = target_ip
        self.target_port = target_port
        self.timeout = timeout
        self.logger = logging.getLogger(self.__class__.__name__)

    @abc.abstractmethod
    def send_payload(self, payload: bytes, endpoint: str = "") -> Any:
        pass

    @abc.abstractmethod
    def check_alive(self) -> bool:
        pass

class HTTPAdapter(BaseProtocolAdapter):
    """
    Adapter for HTTP services (REST, CGI, etc.)
    """
    def send_payload(self, payload: bytes, endpoint: str = "") -> requests.Response:
        url = f"http://{self.target_ip}:{self.target_port}/{endpoint.lstrip('/')}"
        
        # Check if payload is a full HTTP request (heuristic)
        if payload.startswith(b"POST") or payload.startswith(b"GET"):
            return self._send_raw_http(payload)
            
        try:
            self.logger.info(f"Sending POST to {url} ({len(payload)} bytes)")
            resp = requests.post(url, data=payload, timeout=self.timeout)
            return resp
        except Exception as e:
            self.logger.error(f"HTTP request failed: {e}")
            raise

    def _send_raw_http(self, payload: bytes) -> requests.Response:
        """Sends a raw HTTP request via socket and attempts to parse basic response"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((self.target_ip, self.target_port))
            s.sendall(payload)
            
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    response += chunk
            except socket.timeout:
                pass
            
            # Simplified mock-response for raw socket
            mock_resp = requests.Response()
            mock_resp.status_code = 200 if b"200 OK" in response else 500
            mock_resp._content = response
            return mock_resp

    def check_alive(self) -> bool:
        try:
            url = f"http://{self.target_ip}:{self.target_port}/"
            requests.get(url, timeout=1)
            return True
        except:
            return False

class TCPRawAdapter(BaseProtocolAdapter):
    """
    Adapter for raw TCP services (Telnet, custom protocols)
    """
    def send_payload(self, payload: bytes, endpoint: str = "") -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect((self.target_ip, self.target_port))
            s.sendall(payload)
            
            response = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    response += chunk
            except socket.timeout:
                pass
            return response

    def check_alive(self) -> bool:
        try:
            with socket.create_connection((self.target_ip, self.target_port), timeout=1):
                return True
        except:
            return False
