"""
HTTP Parser personalizado para el Portal Cautivo
Implementa parsing manual de protocolo HTTP sin dependencias externas
"""

import re
from urllib.parse import unquote
from typing import Dict, Optional, Tuple, List


def parse_key_value_pairs(data: str, delimiter: str = '&') -> Dict[str, str]:
    """Parsea strings en formato key=value&key2=value2"""
    pairs = {}
    if not data:
        return pairs
        
    for pair in data.split(delimiter):
        pair = pair.strip()
        if not pair:
            continue
        if '=' in pair:
            key, value = pair.split('=', 1)
            key = unquote(key.strip())
            value = unquote(value.strip())
            pairs[key] = value
    return pairs


class HTTPRequest:
    """
    Representa una solicitud HTTP parseada con métodos helper
    para acceder a datos comunes del portal cautivo
    """
    
    def __init__(self, method: str = "", path: str = "", version: str = "HTTP/1.1", 
                 headers: Dict[str, str] = None, body: str = "", raw_data: bytes = b""):
        self.method = method.upper() if method else ""
        self.path = path
        self.version = version
        self.headers = headers or {}
        self.body = body
        self.raw_data = raw_data
        
        self.query_params = self._parse_query_params()
        self.form_data = self._parse_form_data()
        self.cookies = self._parse_cookies()
        
        self.path_parts = self.path.split('?')[0].split('/')[1:]
        self.requested_file = self.path_parts[-1] if self.path_parts else ""
    
    def _parse_query_params(self) -> Dict[str, str]:
        if '?' not in self.path:
            return {}
        
        query_string = self.path.split('?', 1)[1]
        return parse_key_value_pairs(query_string)
    
    def _parse_form_data(self) -> Dict[str, str]:
        if (self.method == 'POST' and 
            'application/x-www-form-urlencoded' in self.headers.get('content-type', '')):
            return parse_key_value_pairs(self.body)
        return {}
    
    def _parse_cookies(self) -> Dict[str, str]:
        cookie_header = self.headers.get('cookie', '')
        cookies = {}
        
        for cookie_part in cookie_header.split(';'):
            cookie_part = cookie_part.strip()
            if '=' in cookie_part:
                key, value = cookie_part.split('=', 1)
                key = unquote(key.strip())
                value = unquote(value.strip())
                cookies[key] = value
            
        return cookies
    
    def get_header(self, name: str, default: str = None) -> Optional[str]:
        name_lower = name.lower()
        return self.headers.get(name_lower, default)
    
    def get_cookie(self, name: str, default: str = None) -> Optional[str]:
        return self.cookies.get(name, default)
    
    def has_valid_session(self) -> bool:
        return 'session_id' in self.cookies and self.cookies['session_id']
    
    def is_public_request(self) -> bool:
        public_paths = ['/login', '/styles/', '/js/', '/favicon.ico', '/css/']
        return any(self.path.startswith(path) for path in public_paths)
    
    def get_content_length(self) -> int:
        try:
            return int(self.get_header('content-length', 0))
        except (ValueError, TypeError):
            return 0
    
    def get_user_agent(self) -> str:
        return self.get_header('user-agent', 'Unknown')
    
    def get_client_ip(self, client_address: Tuple[str, int]) -> str:
        x_forwarded_for = self.get_header('x-forwarded-for')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return client_address[0]
    
    def wants_keep_alive(self) -> bool:
        connection = (self.get_header('connection', '') or '').lower()
        if self.version == 'HTTP/1.1':
            return connection != 'close'
        else:
            return connection == 'keep-alive'
    
    def __repr__(self) -> str:
        return f"HTTPRequest(method='{self.method}', path='{self.path}', version='{self.version}')"
    
    def __str__(self) -> str:
        return f"{self.method} {self.path} {self.version}"


class HTTPResponse:
    """
    Representa una respuesta HTTP con métodos helper para construcciones comunes
    """
    
    STATUS_CODES = {
        200: "OK",
        302: "Found",
        400: "Bad Request",
        401: "Unauthorized", 
        404: "Not Found",
        500: "Internal Server Error"
    }
    
    def __init__(self, status_code: int = 200, headers: Dict[str, str] = None, 
                 body: str = "", version: str = "HTTP/1.1"):
        self.status_code = status_code
        self.headers = headers or {}
        self.body = body
        self.version = version
        self._raw_content = None
        self._cookies = []
        
        if 'content-type' not in self.headers:
            self.headers['Content-Type'] = 'text/html; charset=utf-8'
    
    def set_cookie(self, name: str, value: str, max_age: int = None, path: str = "/") -> None:
        cookie_parts = [f"{name}={value}"]
        if max_age:
            cookie_parts.append(f"Max-Age={max_age}")
        if path:
            cookie_parts.append(f"Path={path}")
        
        self._cookies.append('; '.join(cookie_parts))
    
    def delete_cookie(self, name: str, path: str = "/") -> None:
        self.set_cookie(name, "", max_age=0, path=path)
    
    def redirect(self, location: str) -> None:
        self.status_code = 302
        self.headers['Location'] = location
        self.body = f"Redirecting to {location}"
    
    def to_bytes(self) -> bytes:
        status_line = f"{self.version} {self.status_code} {self.STATUS_CODES.get(self.status_code, 'Unknown')}"
        
        headers_lines = []
        
        for key, value in self.headers.items():
            safe_value = str(value).replace('\r', '').replace('\n', '')
            headers_lines.append(f"{key}: {safe_value}")
        
        for cookie in self._cookies:
            safe_cookie = cookie.replace('\r', '').replace('\n', '')
            headers_lines.append(f"Set-Cookie: {safe_cookie}")
        
        if self._raw_content is not None:
            body_bytes = self._raw_content
        else:
            body_bytes = (self.body or "").encode('utf-8')
        
        content_length_present = False
        for i, h in enumerate(headers_lines):
            if h.lower().startswith('content-length:'):
                headers_lines[i] = f"Content-Length: {len(body_bytes)}"
                content_length_present = True
                break
        if not content_length_present and len(body_bytes) > 0:
            headers_lines.append(f"Content-Length: {len(body_bytes)}")
        
        header_section = status_line + "\r\n" + "\r\n".join(headers_lines) + "\r\n\r\n"
        return header_section.encode('utf-8') + body_bytes
    
    @classmethod
    def make_redirect(cls, location: str) -> 'HTTPResponse':
        response = cls(302)
        response.headers['Location'] = location
        response.body = f"Redirecting to {location}"
        return response
    
    @classmethod
    def make_html_response(cls, html_content: str, status_code: int = 200) -> 'HTTPResponse':
        response = cls(status_code)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.body = html_content
        return response
    
    @classmethod
    def make_error_response(cls, status_code: int, message: str = "") -> 'HTTPResponse':
        if not message:
            message = cls.STATUS_CODES.get(status_code, "Error")
        
        html = f"""
        <html>
            <head><title>{status_code} {message}</title></head>
            <body>
                <h1>{status_code} {message}</h1>
                <p>The server encountered an error while processing your request.</p>
            </body>
        </html>
        """
        return cls.make_html_response(html, status_code)


class HTTPParser:
    """
    Parser HTTP personalizado que convierte bytes crudos en objetos HTTPRequest
    y ayuda a construir respuestas HTTPResponse
    """
    
    REQUEST_LINE_REGEX = re.compile(r'^([A-Z]+)\s+([^\s]+)\s+(HTTP/\d\.\d)$')
    
    def __init__(self, max_request_size: int = 8192):
        self.max_request_size = max_request_size
    
    def parse_request(self, raw_data: bytes, client_address: Tuple[str, int] = None) -> HTTPRequest:
        try:
            if len(raw_data) > self.max_request_size:
                return self._create_invalid_request("Request too large")
            
            if not raw_data:
                return self._create_invalid_request("Empty request data")
            
            if b'\r\n\r\n' not in raw_data:
                return self._create_invalid_request("Incomplete headers")
            
            header_section_bytes, body_bytes = raw_data.split(b'\r\n\r\n', 1)
            header_text = header_section_bytes.decode('utf-8', errors='replace')
            
            lines = header_text.split('\r\n')
            if not lines:
                return self._create_invalid_request("No request data")
            
            method, path, version = self._parse_request_line(lines[0])
            headers = self._parse_headers(lines[1:])
            
            content_length = 0
            try:
                content_length = int(headers.get('content-length', 0))
            except (ValueError, TypeError):
                content_length = 0
            
            if content_length > 0 and len(body_bytes) < content_length:
                return self._create_invalid_request("Incomplete body")
            
            if content_length > 0 and len(body_bytes) > content_length:
                body_bytes = body_bytes[:content_length]
            
            body = body_bytes.decode('utf-8', errors='replace')
            
            return HTTPRequest(
                method=method,
                path=path,
                version=version,
                headers=headers,
                body=body,
                raw_data=raw_data
            )
            
        except Exception as e:
            return self._create_invalid_request(f"Parse error: {str(e)}")
    
    def _parse_request_line(self, request_line: str) -> Tuple[str, str, str]:
        match = self.REQUEST_LINE_REGEX.match(request_line)
        if not match:
            raise ValueError(f"Invalid request line: {request_line}")
        
        method, path, version = match.groups()
        
        try:
            path = unquote(path)
        except Exception:
            pass
            
        return method, path, version
    
    def _parse_headers(self, header_lines: List[str]) -> Dict[str, str]:
        headers = {}
        for line in header_lines:
            if not line.strip():
                continue
                
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        return headers
    
    def _create_invalid_request(self, error_message: str) -> HTTPRequest:
        return HTTPRequest(
            method="INVALID",
            path="",
            version="HTTP/1.1",
            headers={},
            body="",
            raw_data=b""
        )
    
    def build_static_response(self, content: bytes, content_type: str) -> HTTPResponse:
        response = HTTPResponse(200)
        response.headers['Content-Type'] = content_type
        
        if content_type.startswith('text/'):
            response.body = content.decode('utf-8', errors='replace')
        else:
            response._raw_content = content
            
        return response
    
    def build_redirect_response(self, location: str) -> HTTPResponse:
        return HTTPResponse.make_redirect(location)
    
    def build_html_response(self, html_content: str, status_code: int = 200, 
                          cookies: Dict[str, str] = None) -> HTTPResponse:
        response = HTTPResponse.make_html_response(html_content, status_code)
        
        if cookies:
            for name, value in cookies.items():
                response.set_cookie(name, value)
                
        return response
    
    def build_error_response(self, status_code: int, message: str = "") -> HTTPResponse:
        return HTTPResponse.make_error_response(status_code, message)