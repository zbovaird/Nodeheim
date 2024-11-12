# src/api/__init__.py

from .routes import APIRoutes

def init_api(app, data_dir='src/data'):
    routes = APIRoutes(data_dir)
    routes.register_routes(app)