# api/index.py - Vercel Serverless Entry Point
# Este archivo es requerido por Vercel para manejar la app Flask correctamente.

from app import app

# Vercel espera encontrar una variable 'app' o 'application' aquí
# Esta es la forma estándar de desplegar Flask en Vercel
