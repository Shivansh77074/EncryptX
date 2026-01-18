import os
from urllib import response
from wsgiref import headers
from flask import Flask, app, request
from flask_cors import CORS
from config import get_config, Config
from routes.auth_routes import auth_bp
from routes.crypto_routes import crypto_bp


def create_app(config_name=None, env='development'):
    """
    Application factory pattern with security hardening
    
    Args:
        config_name: Configuration environment ('development', 'production')
    
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Load configuration
    if config_name:
        app.config.from_object(config_name)
    else:
        config_class = get_config(env)
        app.config.from_object(config_class, env)
    
  
    # TODO: In production, define CORS_ORIGINS in config.py as a list of trusted domains:
    # CORS_ORIGINS = ["https://yourdomain.com", "https://admin.yourdomain.com"]
    # Then replace origins="*" with origins=app.config['CORS_ORIGINS']
    # Enable CORS with strict settings
    CORS(
        app,
        supports_credentials=True,
        origins=app.config['CORS_ORIGINS'],
        max_age=app.config.get('CORS_MAX_AGE', 3600),
        allow_headers=['Content-Type', 'X-CSRF-Token'],
        methods=['GET', 'POST', 'OPTIONS']
    )
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(crypto_bp, url_prefix='/api')
    
    # ===== Security Headers =====
    @app.after_request
    def add_security_headers(response):
        headers = app.config.get('SECURITY_HEADERS', {})
        for header, value in headers.items():
            response.headers[header] = value

        # Remove server info disclosure
        response.headers.pop('Server', None)
       
        if app.config.get('ENV_NAME') != 'development':
            response.headers['Server'] = 'SecureCrypt'  # fake server name in production

        return response

    
    # ===== Error Handlers (Generic messages to prevent info leakage) =====
    
    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad request'}, 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return {'error': 'Unauthorized'}, 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return {'error': 'Forbidden'}, 403
    
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not found'}, 404
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        return {'error': 'Method not allowed'}, 405
    
    @app.errorhandler(413)
    def request_entity_too_large(error):
        return {'error': 'Request too large'}, 413
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return {'error': 'Too many requests'}, 429
    
    @app.errorhandler(500)
    def internal_error(error):
        # Never expose internal error details
        return {'error': 'Internal server error'}, 500
    
    # ===== Request Hooks =====
    
    @app.before_request
    def before_request_security():
        """Security checks before processing requests"""
        
        # Block requests with suspicious headers
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) > 500:
            return {'error': 'Invalid request'}, 400
        
        # Validate content type for POST requests
        if request.method == 'POST' and not request.path.startswith('/api/'):
            if not request.is_json:
                return {'error': 'Content-Type must be application/json'}, 400
    
    # ===== Health Check Endpoint =====
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for monitoring"""
        return {'status': 'healthy', 'service': 'SecureCrypt'}, 200
    
    # ====== Only for the Debugors=====
    
    # @app.route('/debug/routes') 
    # def list_routes():
    #     """Debug: List all registered routes"""
    #     import urllib
    #     output = []
    #     for rule in app.url_map.iter_rules():
    #         methods = ','.join(sorted(rule.methods))
    #         output.append(f"{rule.endpoint}: {rule.rule} [{methods}]")
    #     return {'routes': output}
    
    return app


def main():
    """Main entry point for running the application"""
    
    # =========================
    # Get environment safely
    # APP_ENV should be set to 'development' or 'production'
    # =========================

    # TODO: Always set APP_ENV=production in production servers
    # Never run Flask dev server in production!
    # Use a proper WSGI server like gunicorn or uWSGI
    env = os.environ.get('APP_ENV', 'development').lower()  # read environment

    # Get config without passing env
    config_class = get_config()  # ✅ call with no arguments

    # Create app with config
    app = create_app(config_class)

    # Store env inside app.config for after_request hook
    app.config['ENV_NAME'] = env

    
    # Security notice
    print("=" * 70)
    print("  SECURECRYPT - PRODUCTION-GRADE CRYPTOGRAPHIC WEB APPLICATION")
    print("=" * 70)
    print("\n🔒 Security Features Enabled:")
    print("  ✓ AES-256-GCM Encryption (Recommended)")
    print("  ✓ ChaCha20-Poly1305 (Recommended)")
    print("  ✓ Camellia-256-CBC")
    print("  ✓ RSA-2048 with OAEP")
    print("  ✓ Triple DES (3DES) - Legacy")
    print("  ✓ Blowfish-256")
    print("  ✓ Twofish-256")
    print("  ✗ DES - REMOVED (Insecure)")
    print("  ✗ RC4 - REMOVED (Broken)")
    print("\n🛡️  Security Controls:")
    print("  ✓ PBKDF2-SHA256 (600k iterations)")
    print("  ✓ Unique salts per encryption")
    print("  ✓ Zero data persistence (memory only)")
    print("  ✓ Session-based authentication")
    print("  ✓ CSRF protection")
    print("  ✓ Rate limiting")
    print("  ✓ Input validation & sanitization")
    print("  ✓ Security headers (CSP, HSTS, etc.)")
    print("  ✓ Constant-time password comparison")
    print("  ✓ Enhanced password requirements (12+ chars, special chars)")
    print("  ✓ Generic error messages")
    print("  ✓ No debug mode")
    
    if env == 'development':
        print("\n⚠️  DEVELOPMENT MODE")
        print("  • HTTPS not enforced")
        print("  • Use HTTPS proxy in production")
        print("\n🌐 Server: http://localhost:5000/api")
    else:
        print("\n🚀 PRODUCTION MODE")
        print("  • All security features active")
        print("  • HTTPS required")
        print("\n🌐 Server: https://your-domain.com")
    
    print("=" * 70 + "\n")
    
    # Run application
    # NEVER use debug=True in production
    # Use a production WSGI server (gunicorn, uWSGI) instead of Flask dev server


    if env == 'development':
        # ✅ Safe local testing
        print("⚠️ Running in DEVELOPMENT mode on localhost (safe for testing)")
        print("  • Debug mode is OFF for security")
        print("  • Access your app at: http://127.0.0.1:5000/api")
    
        app.run(
            debug=False,          # Always False to prevent info leaks
            host='127.0.0.1',    # Localhost only
            port=5000,
            threaded=True
        )

    else:
        # ❌ Block running dev server in production
        print("❌ ERROR: Flask development server MUST NOT be used in production!")
        print("Use a production WSGI server like gunicorn or uWSGI:")
        print("  gunicorn -w 4 -b 0.0.0.0:8000 'main:create_app()'")
        print("Exiting to prevent insecure deployment.")
        exit(1)



if __name__ == '__main__':
    main()