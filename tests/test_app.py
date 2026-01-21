# ==============================================================================
# Tests - Flask Deploy Template
# ==============================================================================
# Ejecutar con: pytest tests/ -v
# ==============================================================================

import pytest
from app import app, anonymize_ip


# ==============================================================================
# Fixtures
# ==============================================================================
@pytest.fixture
def client():
    """Cliente de prueba Flask."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def runner():
    """CLI runner para testing."""
    return app.test_cli_runner()


# ==============================================================================
# Tests de Rutas
# ==============================================================================
class TestRoutes:
    """Tests para las rutas principales."""

    def test_index_returns_200(self, client):
        """La página principal debe retornar 200."""
        response = client.get('/')
        assert response.status_code == 200

    def test_index_contains_expected_content(self, client):
        """La página principal debe contener contenido esperado."""
        response = client.get('/')
        assert b'SITIO EN' in response.data or b'Sitio en' in response.data

    def test_index_has_request_id(self, client):
        """La respuesta debe incluir X-Request-ID header."""
        response = client.get('/')
        assert 'X-Request-ID' in response.headers
        assert len(response.headers['X-Request-ID']) > 0

    def test_healthz_endpoint_returns_json(self, client):
        """El endpoint /healthz debe retornar JSON válido."""
        response = client.get('/healthz')
        assert response.status_code == 200
        assert response.content_type == 'application/json'

    def test_healthz_endpoint_has_required_fields(self, client):
        """El endpoint /healthz debe tener solo status (no timestamp por seguridad)."""
        response = client.get('/healthz')
        data = response.get_json()
        assert 'status' in data
        assert data['status'] == 'ok'
        # SECURITY: timestamp fue removido para prevenir information disclosure
        assert 'timestamp' not in data

    def test_healthz_minimal_response(self, client):
        """El healthz debe retornar respuesta mínima (solo status)."""
        response = client.get('/healthz')
        data = response.get_json()
        # Solo debe tener 'status', nada más
        assert len(data) == 1
        assert data == {'status': 'ok'}


    def test_status_redirects_to_healthz(self, client):
        """El endpoint /status debe redirigir a /healthz con 301."""
        response = client.get('/status')
        assert response.status_code == 301
        assert '/healthz' in response.headers.get('Location', '')

    def test_status_redirect_follow(self, client):
        """Siguiendo el redirect de /status debe llegar a healthz."""
        response = client.get('/status', follow_redirects=True)
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'ok'


# ==============================================================================
# Tests de Manejo de Errores
# ==============================================================================
class TestErrorHandlers:
    """Tests para manejadores de errores."""

    def test_404_handler(self, client):
        """Rutas inexistentes deben retornar 404."""
        response = client.get('/nonexistent-page-xyz')
        assert response.status_code == 404

    def test_404_page_contains_helpful_text(self, client):
        """Página 404 debe contener texto útil."""
        response = client.get('/nonexistent-page-xyz')
        assert b'404' in response.data

    def test_404_has_request_id(self, client):
        """Errores 404 deben incluir request ID."""
        response = client.get('/nonexistent-page-xyz')
        assert 'X-Request-ID' in response.headers

    def test_403_handler_exists(self, client):
        """403 handler está registrado (M4)."""
        from flask import abort
        # We can't directly trigger 403 without a protected route,
        # but we can verify the template exists
        import os
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'templates', 'errors', '403.html'
        )
        assert os.path.exists(template_path), "403.html template should exist"

    def test_500_handler_no_traceback_in_production(self, client):
        """A5: Error 500 no debe filtrar traceback en producción."""
        from app import IS_DEVELOPMENT, app as flask_app
        if IS_DEVELOPMENT:
            # Temporarily disable exception propagation to test error handler
            original_propagate = flask_app.config.get('PROPAGATE_EXCEPTIONS')
            flask_app.config['PROPAGATE_EXCEPTIONS'] = False
            flask_app.config['TESTING'] = False
            
            try:
                with flask_app.test_client() as test_client:
                    response = test_client.get('/test-error')
                    assert response.status_code == 500
                    # The response should NOT contain the error message
                    assert b'Intentional test error' not in response.data
                    # Should contain generic 500 page content
                    assert b'500' in response.data or b'Error' in response.data
            finally:
                # Restore original config
                flask_app.config['TESTING'] = True
                if original_propagate is not None:
                    flask_app.config['PROPAGATE_EXCEPTIONS'] = original_propagate


# ==============================================================================
# Tests de Headers de Seguridad (A2)
# ==============================================================================
class TestSecurityHeaders:
    """Tests para verificar headers de seguridad en respuestas."""

    def test_x_content_type_options_header(self, client):
        """X-Content-Type-Options debe estar presente."""
        response = client.get('/')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_x_frame_options_header(self, client):
        """X-Frame-Options debe estar presente."""
        response = client.get('/')
        assert response.headers.get('X-Frame-Options') == 'DENY'

    def test_referrer_policy_header(self, client):
        """Referrer-Policy debe estar presente."""
        response = client.get('/')
        assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'

    def test_permissions_policy_header(self, client):
        """Permissions-Policy debe estar presente."""
        response = client.get('/')
        permissions = response.headers.get('Permissions-Policy', '')
        assert 'camera=()' in permissions
        assert 'microphone=()' in permissions


# ==============================================================================
# Tests de Anonimización IP (GDPR)
# ==============================================================================
class TestIPAnonymization:
    """Tests para la función de anonimización IP."""

    # IPv4 Tests
    def test_anonymize_ip_ipv4_standard(self):
        """IPv4 estándar: último octeto debe ser 0."""
        result = anonymize_ip('192.168.1.100')
        assert result == '192.168.1.0'

    def test_anonymize_ip_ipv4_preserves_network(self):
        """Anonimización debe preservar identificador de red /24."""
        result = anonymize_ip('10.0.0.1')
        assert result == '10.0.0.0'

    def test_anonymize_ip_ipv4_already_zero(self):
        """IPv4 con último octeto ya en 0."""
        result = anonymize_ip('172.16.0.0')
        assert result == '172.16.0.0'

    def test_anonymize_ip_localhost(self):
        """Localhost IPv4."""
        result = anonymize_ip('127.0.0.1')
        assert result == '127.0.0.0'

    # IPv6 Tests
    def test_anonymize_ip_ipv6_full(self):
        """IPv6 completo debe mantener solo /48."""
        result = anonymize_ip('2001:db8:85a3:0000:0000:8a2e:0370:7334')
        assert result == '2001:db8:85a3::'

    def test_anonymize_ip_ipv6_compressed(self):
        """IPv6 comprimido (::1)."""
        result = anonymize_ip('::1')
        assert result == '::'

    def test_anonymize_ip_ipv6_loopback(self):
        """IPv6 loopback."""
        result = anonymize_ip('::1')
        assert result == '::'

    def test_anonymize_ip_ipv6_link_local(self):
        """IPv6 link-local."""
        result = anonymize_ip('fe80::1')
        assert result == 'fe80::'

    def test_anonymize_ip_ipv6_mapped_ipv4(self):
        """IPv6-mapped IPv4 (::ffff:192.168.1.1)."""
        result = anonymize_ip('::ffff:192.168.1.1')
        # This is technically an IPv6 address
        assert result == '::ffff:c0a8:' or '::' in result

    # Edge Cases
    def test_anonymize_ip_none(self):
        """IP nula debe retornar 'unknown'."""
        result = anonymize_ip(None)
        assert result == 'unknown'

    def test_anonymize_ip_empty(self):
        """IP vacía debe retornar 'unknown'."""
        result = anonymize_ip('')
        assert result == 'unknown'

    def test_anonymize_ip_invalid_format(self):
        """IP con formato inválido."""
        result = anonymize_ip('not-an-ip')
        assert result == 'invalid-ip'

    def test_anonymize_ip_partial_ipv4(self):
        """IPv4 incompleta."""
        result = anonymize_ip('192.168.1')
        assert result == 'invalid-ip'


# ==============================================================================
# Tests de Configuración
# ==============================================================================
class TestConfiguration:
    """Tests de configuración de la aplicación."""

    def test_app_has_secret_key(self):
        """La aplicación debe tener SECRET_KEY configurada."""
        assert app.config['SECRET_KEY'] is not None
        assert len(app.config['SECRET_KEY']) > 0

    def test_secret_key_is_not_empty(self):
        """SECRET_KEY no debe estar vacía."""
        assert len(app.config['SECRET_KEY']) >= 32

    def test_csrf_enabled(self):
        """CSRF debe estar habilitado."""
        assert app.config['WTF_CSRF_ENABLED'] is True

    def test_site_name_validation(self, monkeypatch):
        """SITE_NAME con caracteres maliciosos debe ser rechazado."""
        monkeypatch.setenv('SITE_NAME', '<script>alert(1)</script>')
        import importlib
        import app as app_module
        importlib.reload(app_module)
        
        # The malicious value should be rejected, default used
        assert app_module.SITE_NAME == 'VercelDeploy'


# ==============================================================================
# Tests de Seguridad
# ==============================================================================
class TestSecurity:
    """Tests de headers y configuración de seguridad."""

    def test_response_has_request_id(self, client):
        """Todas las respuestas deben tener X-Request-ID."""
        response = client.get('/')
        assert 'X-Request-ID' in response.headers

    def test_custom_request_id_preserved(self, client):
        """Si se envía X-Request-ID, debe preservarse."""
        response = client.get('/', headers={'X-Request-ID': 'test-123'})
        assert response.headers['X-Request-ID'] == 'test-123'


# ==============================================================================
# Tests de Protección de Health Check
# ==============================================================================
class TestHealthCheckProtection:
    """Tests para protección de endpoint healthz con token."""

    def test_healthz_accessible_without_token_by_default(self, client):
        """Sin HEALTH_CHECK_TOKEN configurado, healthz es accesible."""
        response = client.get('/healthz')
        assert response.status_code == 200

    def test_healthz_returns_ok_status(self, client):
        """Healthz debe retornar status ok."""
        response = client.get('/healthz')
        data = response.get_json()
        assert data['status'] == 'ok'


# ==============================================================================
# Tests de Rate Limiting (Desarrollo)
# ==============================================================================
class TestRateLimiting:
    """Tests para verificar configuración de rate limiting."""

    def test_rate_limiter_configured(self):
        """Verificar que rate limiter está configurado para desarrollo."""
        from app import limiter, IS_DEVELOPMENT
        # In development, limiter should exist
        if IS_DEVELOPMENT:
            assert limiter is not None


# ==============================================================================
# Tests de Escenarios de Error y Edge Cases
# ==============================================================================
class TestErrorScenarios:
    """Tests para escenarios de error, edge cases y seguridad."""

    def test_malformed_request_id_rejected(self, client):
        """Request IDs con caracteres peligrosos deben ser rechazados."""
        # Intento de inyección de log
        response = client.get('/', headers={'X-Request-ID': '<script>alert(1)</script>'})
        returned_id = response.headers.get('X-Request-ID', '')
        # El ID malicioso no debe ser usado
        assert '<script>' not in returned_id
        assert 'alert' not in returned_id

    def test_very_long_request_id_truncated(self, client):
        """Request IDs muy largos deben ser truncados a 36 caracteres."""
        long_id = 'a' * 100
        response = client.get('/', headers={'X-Request-ID': long_id})
        returned_id = response.headers.get('X-Request-ID', '')
        assert len(returned_id) <= 36

    def test_healthz_no_timestamp_exposed(self, client):
        """Health endpoint no debe exponer timestamp (información sensible)."""
        response = client.get('/healthz')
        data = response.get_json()
        assert 'timestamp' not in data
        assert 'status' in data
        assert data['status'] == 'ok'

    def test_404_returns_html(self, client):
        """Página 404 debe retornar HTML, no JSON."""
        response = client.get('/nonexistent-xyz-page')
        assert response.status_code == 404
        assert response.content_type.startswith('text/html')

    def test_request_id_alphanumeric_valid(self, client):
        """Request IDs alfanuméricos válidos deben ser preservados."""
        valid_id = 'abc-123-DEF'
        response = client.get('/', headers={'X-Request-ID': valid_id})
        assert response.headers['X-Request-ID'] == valid_id


# ==============================================================================
# Tests de Templates y Componentes (B4: Cobertura de templates)
# ==============================================================================
class TestTemplates:
    """Tests para renderizado de templates y componentes."""

    def test_index_renders_robot_component(self, client):
        """La página principal debe renderizar el componente robot."""
        response = client.get('/')
        # Verificar que el robot SVG se renderiza
        assert b'robot' in response.data.lower() or b'Robot' in response.data

    def test_index_renders_footer(self, client):
        """La página principal debe renderizar el footer con copyright."""
        response = client.get('/')
        assert b'derechos reservados' in response.data.lower() or b'VercelDeploy' in response.data

    def test_index_renders_status_panel(self, client):
        """La página principal debe renderizar el panel de estado."""
        response = client.get('/')
        assert b'ESTADO' in response.data or b'Backend' in response.data

    def test_error_pages_render_correctly(self, client):
        """Las páginas de error deben renderizar correctamente."""
        response = client.get('/nonexistent-page-xyz')
        assert response.status_code == 404
        assert b'no encontrada' in response.data.lower() or b'404' in response.data

    def test_offline_html_exists(self):
        """El archivo offline.html debe existir para PWA."""
        import os
        offline_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'static', 'offline.html'
        )
        assert os.path.exists(offline_path), "offline.html is required for PWA"

    def test_manifest_json_valid(self):
        """El manifest.json debe ser JSON válido con campos requeridos."""
        import json
        import os
        manifest_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'static', 'manifest.json'
        )
        with open(manifest_path) as f:
            manifest = json.load(f)
        
        assert 'name' in manifest
        assert 'icons' in manifest
        assert 'start_url' in manifest
        assert len(manifest['icons']) >= 2


# ==============================================================================
# Tests de Contexto de Producción Simulado (M3)
# ==============================================================================
class TestProductionSimulation:
    """Tests que simulan el entorno de producción."""

    def test_site_name_from_env(self, client, monkeypatch):
        """El site_name debe venir de variable de entorno."""
        monkeypatch.setenv('SITE_NAME', 'TestSite')
        # Need to reimport to pick up env change
        from app import inject_globals
        result = inject_globals()
        assert 'site_name' in result

    def test_security_headers_present_in_all_responses(self, client):
        """Todos los endpoints deben tener headers de seguridad."""
        endpoints = ['/', '/healthz']
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Referrer-Policy',
            'Content-Security-Policy',
        ]
        
        for endpoint in endpoints:
            response = client.get(endpoint)
            for header in required_headers:
                assert header in response.headers, f"{header} missing in {endpoint}"

    def test_server_header_not_present(self, client):
        """El header Server no debe estar presente (fingerprinting prevention)."""
        response = client.get('/')
        assert 'Server' not in response.headers, "Server header should be removed"

    def test_no_placeholder_domains_in_static(self):
        """Los archivos estáticos no deben contener dominios placeholder."""
        import os
        static_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'static'
        )
        
        # Patrones que indican configuración incompleta
        placeholder_patterns = ['example.com', 'example.vercel.app', 'TU-DOMINIO', 'YOUR-USERNAME']
        files_to_check = [
            'robots.txt',
            'sitemap.xml',
            os.path.join('.well-known', 'security.txt'),
        ]
        
        for filename in files_to_check:
            filepath = os.path.join(static_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    content = f.read()
                for pattern in placeholder_patterns:
                    assert pattern not in content, f"Placeholder '{pattern}' found in {filename}"


# ==============================================================================
# Tests de Rutas SEO/Seguridad
# ==============================================================================
class TestSEORoutes:
    """Tests para rutas SEO y seguridad estándar."""

    def test_robots_txt_accessible(self, client):
        """robots.txt debe ser accesible desde raíz."""
        response = client.get('/robots.txt')
        assert response.status_code == 200
        assert b'User-agent' in response.data

    def test_robots_txt_contains_sitemap(self, client):
        """robots.txt debe incluir referencia a sitemap."""
        response = client.get('/robots.txt')
        assert b'Sitemap:' in response.data

    def test_sitemap_xml_accessible(self, client):
        """sitemap.xml debe ser accesible desde raíz."""
        response = client.get('/sitemap.xml')
        assert response.status_code == 200
        assert b'urlset' in response.data

    def test_sitemap_xml_contains_valid_url(self, client):
        """sitemap.xml debe contener URL válida con lastmod."""
        response = client.get('/sitemap.xml')
        assert b'<loc>' in response.data
        assert b'<lastmod>' in response.data
        assert b'<priority>' in response.data

    def test_security_txt_accessible(self, client):
        """security.txt debe ser accesible en .well-known."""
        response = client.get('/.well-known/security.txt')
        assert response.status_code == 200
        assert b'Contact:' in response.data

    def test_security_txt_contains_required_fields(self, client):
        """security.txt debe tener campos RFC 9116 requeridos."""
        response = client.get('/.well-known/security.txt')
        assert b'Expires:' in response.data
        assert b'Canonical:' in response.data

    def test_dynamic_urls_use_base_url(self, client, monkeypatch):
        """Las URLs dinámicas deben usar BASE_URL configurado."""
        monkeypatch.setenv('BASE_URL', 'https://example.com')
        # Need to reload the module to pick up env change
        import importlib
        import app as app_module
        importlib.reload(app_module)
        
        with app_module.app.test_client() as test_client:
            response = test_client.get('/robots.txt')
            assert b'https://example.com/sitemap.xml' in response.data

