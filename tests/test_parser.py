#!/usr/bin/env python3
"""
Script de prueba simple para el HTTP Parser
"""

import sys
import os

# Agregar el directorio raíz del proyecto al path de Python
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(project_root, 'src')
sys.path.insert(0, src_path)

from server.http_parser import HTTPParser, HTTPResponse

def test_basic_parsing():
    """Prueba parsing de requests básicas"""
    parser = HTTPParser()
    
    # Test 1: GET simple
    print("=== Test 1: GET simple ===")
    get_request = b"GET /login HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: TestBrowser\r\n\r\n"
    request = parser.parse_request(get_request)
    print(f"Método: {request.method}")
    print(f"Path: {request.path}")
    print(f"Headers: {request.headers}")
    print(f"User-Agent: {request.get_user_agent()}")
    success = request.method == "GET" and request.path == "/login"
    print("✅ GET simple - PASÓ" if success else "❌ GET simple - FALLÓ")
    print()
    
    # Test 2: POST con datos de formulario
    print("=== Test 2: POST con formulario ===")
    post_data = "username=testuser&password=testpass"
    post_request = f"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(post_data)}\r\n\r\n{post_data}".encode()
    request2 = parser.parse_request(post_request)
    print(f"Método: {request2.method}")
    print(f"Form data: {request2.form_data}")
    success = request2.method == "POST" and "username" in request2.form_data
    print("✅ POST con formulario - PASÓ" if success else "❌ POST con formulario - FALLÓ")
    print()
    
    # Test 3: Request con query parameters
    print("=== Test 3: GET con query string ===")
    query_request = b"GET /search?q=python&page=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
    request3 = parser.parse_request(query_request)
    print(f"Path: {request3.path}")
    print(f"Query params: {request3.query_params}")
    success = "q" in request3.query_params and request3.query_params["q"] == "python"
    print("✅ Query parameters - PASÓ" if success else "❌ Query parameters - FALLÓ")
    print()
    
    # Test 4: Respuestas HTTP
    print("=== Test 4: Respuesta HTML ===")
    html_content = "<html><body><h1>Hola Mundo</h1></body></html>"
    response = HTTPResponse.make_html_response(html_content)
    response_bytes = response.to_bytes()
    print("Respuesta generada correctamente")
    success = b"200 OK" in response_bytes and b"text/html" in response_bytes
    print("✅ Respuesta HTML - PASÓ" if success else "❌ Respuesta HTML - FALLÓ")
    print()
    
    # Test 5: Redirección
    print("=== Test 5: Redirección ===")
    redirect = HTTPResponse.make_redirect("/dashboard")
    redirect_bytes = redirect.to_bytes()
    success = b"302 Found" in redirect_bytes and b"Location: /dashboard" in redirect_bytes
    print("✅ Redirección - PASÓ" if success else "❌ Redirección - FALLÓ")
    print()

def test_error_cases():
    """Prueba casos de error"""
    parser = HTTPParser(max_request_size=100)
    
    print("=== Test 6: Request demasiado grande ===")
    large_request = b"GET /" + b"x" * 200 + b" HTTP/1.1\r\n\r\n"
    request = parser.parse_request(large_request)
    success = request.method == "INVALID"
    print("✅ Request grande detectada - PASÓ" if success else "❌ Request grande detectada - FALLÓ")
    print()

def test_cookies():
    """Prueba parsing de cookies"""
    parser = HTTPParser()
    
    print("=== Test 7: Cookies ===")
    cookie_request = b"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: session_id=abc123; user=test\r\n\r\n"
    request = parser.parse_request(cookie_request)
    print(f"Cookies: {request.cookies}")
    success = request.cookies.get("session_id") == "abc123"
    print("✅ Cookies - PASÓ" if success else "❌ Cookies - FALLÓ")
    print()

if __name__ == "__main__":
    print("🧪 Iniciando pruebas del HTTP Parser...\n")
    
    tests_passed = 0
    tests_failed = 0
    
    # Ejecutar pruebas
    try:
        test_basic_parsing()
        tests_passed += 5
    except Exception as e:
        tests_failed += 5
        print(f"❌ Error en pruebas básicas: {e}")
    
    try:
        test_error_cases()
        tests_passed += 1
    except Exception as e:
        tests_failed += 1
        print(f"❌ Error en pruebas de error: {e}")
    
    try:
        test_cookies()
        tests_passed += 1
    except Exception as e:
        tests_failed += 1
        print(f"❌ Error en pruebas de cookies: {e}")
    
    print(f"📊 Resumen: {tests_passed} pruebas pasadas, {tests_failed} fallidas")
    
    if tests_failed == 0:
        print("🎉 ¡Todas las pruebas pasaron!")
    else:
        print("💥 Algunas pruebas fallaron")
        sys.exit(1)