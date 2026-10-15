import os
import hashlib
import logging
from dotenv import load_dotenv

load_dotenv()

# PostgreSQL only. Set DB_HOST, DB_PORT, DB_NAME, DB_USER and DB_PASSWORD in backend/.env.
# DATABASE_URL, when set, overrides them (Docker and the test suite use it).
DB_PATH = None  # no SQLite file

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL and os.environ.get("DB_NAME"):
    # Quote each part so a space or symbol in a name or password is safe.
    from urllib.parse import quote
    DATABASE_URL = "postgresql://{}:{}@{}:{}/{}".format(
        quote(os.environ.get("DB_USER", "postgres"), safe=""),
        quote(os.environ.get("DB_PASSWORD", ""), safe=""),
        os.environ.get("DB_HOST", "localhost"),
        os.environ.get("DB_PORT", "5432"),
        quote(os.environ["DB_NAME"], safe=""),
    )

try:
    import psycopg2
    from psycopg2 import pool
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    import bcrypt
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
except ImportError:
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()


class Row(dict):
    """Row adapter matching dict and integer index access."""
    def __init__(self, description, values):
        super().__init__()
        self._values = list(values)
        self._keys = [d[0] for d in description] if description else []
        for k, v in zip(self._keys, self._values):
            self[k] = v

    def __getitem__(self, item):
        if isinstance(item, int):
            return self._values[item]
        return super().__getitem__(item)

    def keys(self):
        return self._keys


def _to_pyformat(query: str) -> str:
    """'?' placeholders to psycopg2's '%s'. A '?' inside a quoted literal (such as a URL) is left alone, and a
    literal '%' is doubled, as psycopg2 requires whenever parameters are passed."""
    out = []
    quoted = False
    for ch in query:
        if ch == "'":
            quoted = not quoted
            out.append(ch)
        elif ch == "%":
            out.append("%%")
        elif ch == "?" and not quoted:
            out.append("%s")
        else:
            out.append(ch)
    return "".join(out)


class PostgresCursorWrapper:
    """Wraps a psycopg2 cursor so execute(query, params) handles '?' placeholders cleanly and supports lastrowid."""
    def __init__(self, cursor):
        self._cursor = cursor
        self._lastrowid = None

    def execute(self, query: str, params=None):
        self._lastrowid = None
        if params is not None:
            formatted_query = _to_pyformat(query)
        else:
            formatted_query = query

        stripped = formatted_query.strip().rstrip(";")
        is_insert = stripped.upper().startswith("INSERT INTO")
        has_returning = "RETURNING" in stripped.upper()

        if is_insert and not has_returning:
            # A table without an id column rejects RETURNING id; the savepoint keeps that from aborting the transaction.
            self._cursor.execute("SAVEPOINT returning_id")
            try:
                self._cursor.execute(stripped + " RETURNING id", params)
            except Exception:
                self._cursor.execute("ROLLBACK TO SAVEPOINT returning_id")
                return self._cursor.execute(formatted_query, params)
            row = self._cursor.fetchone() if self._cursor.description else None
            self._cursor.execute("RELEASE SAVEPOINT returning_id")
            if row:
                self._lastrowid = row[0]
            return self

        return self._cursor.execute(formatted_query, params)

    def executemany(self, query: str, seq_of_params):
        return self._cursor.executemany(_to_pyformat(query), seq_of_params)

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return Row(self._cursor.description, row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        return [Row(self._cursor.description, r) for r in rows]

    def __iter__(self):
        return iter(self.fetchall())

    def close(self):
        return self._cursor.close()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        if self._lastrowid is not None:
            return self._lastrowid
        raw_val = getattr(self._cursor, "lastrowid", None)
        return raw_val if (raw_val and raw_val > 0) else None


class PostgresConnectionWrapper:
    """Wraps a pooled psycopg2 connection to provide cursor() and close() returning to pool."""
    def __init__(self, conn, pool_ref):
        self._conn = conn
        self._pool = pool_ref

    def cursor(self):
        return PostgresCursorWrapper(self._conn.cursor())

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        if self._pool and self._conn:
            try:
                if not self._conn.closed:
                    self._pool.putconn(self._conn)
            except Exception as e:
                logging.error(f"Error returning connection to pool: {e}")
            self._conn = None
        elif self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


_pg_pool = None

def get_pg_pool():
    global _pg_pool
    if _pg_pool is None and HAS_PSYCOPG2 and (DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")):
        try:
            _pg_pool = psycopg2.pool.SimpleConnectionPool(
                minconn=1,
                maxconn=15,
                dsn=DATABASE_URL
            )
            logging.info("Connected to the PostgreSQL database pool.")
        except Exception as e:
            logging.error(f"Failed to create the PostgreSQL connection pool: {e}")
    return _pg_pool


def get_db_connection():
    """Returns a pooled PostgreSQL connection."""
    if not DATABASE_URL or not (DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")):
        raise RuntimeError("No database configured. Set DB_HOST, DB_PORT, DB_NAME, DB_USER and DB_PASSWORD in backend/.env.")

    if not HAS_PSYCOPG2:
        raise RuntimeError("psycopg2 is not installed. Please install psycopg2-binary to connect to PostgreSQL.")

    pool_ref = get_pg_pool()
    if pool_ref:
        try:
            raw_conn = pool_ref.getconn()
            if raw_conn.closed != 0:
                pool_ref.putconn(raw_conn, close=True)
                raw_conn = pool_ref.getconn()
            return PostgresConnectionWrapper(raw_conn, pool_ref)
        except Exception as e:
            logging.warning(f"Connection pool acquisition failed, opening direct connection: {e}")

    # Direct connection if the pool had a transient glitch
    try:
        direct_conn = psycopg2.connect(DATABASE_URL)
        return PostgresConnectionWrapper(direct_conn, None)
    except Exception as exc:
        raise RuntimeError(f"Unable to connect to the PostgreSQL database: {exc}")

