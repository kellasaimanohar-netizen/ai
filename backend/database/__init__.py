"""
CertifyAI Database Package
Provides schema migrations, database connections, accounts, activity logging,
and local PDF report generation & storage.
"""

from .connection import get_db_connection, DB_PATH, hash_password, Row
from .schema import init_db, run_migrations
from .pdf_storage import generate_and_store_pdf, get_pdf_path, PDF_DIR

__all__ = [
    "get_db_connection",
    "init_db",
    "run_migrations",
    "hash_password",
    "Row",
    "DB_PATH",
    "PDF_DIR",
    "generate_and_store_pdf",
    "get_pdf_path",
]
