import asyncpg

from app.config import DATABASE_URL, DB_COMMAND_TIMEOUT, DB_POOL_MAX_SIZE

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            # Required when running behind a transaction-mode pooler (Supabase's
            # Supavisor on port 6543, PgBouncer, etc). Such a pooler hands each
            # transaction whatever backend connection is free, so a server-side
            # prepared statement asyncpg cached by name during one transaction
            # may not exist on the connection serving the next one. The failure
            # mode is nasty: not an error at startup, but an intermittent
            # InvalidSQLStatementNameError that only shows up once two requests
            # overlap. Disabling the cache is the documented fix, and it costs
            # nothing against a direct connection -- so it stays on
            # unconditionally rather than being keyed off the port in the URL,
            # which would silently break the moment someone swaps the
            # connection string for a pooled one.
            statement_cache_size=0,
            # Nothing is opened until the first query. Matters on serverless,
            # where an instance that only ever serves a static asset should not
            # be holding database connections open for its whole warm lifetime.
            min_size=0,
            max_size=DB_POOL_MAX_SIZE,
            command_timeout=DB_COMMAND_TIMEOUT,
        )
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
