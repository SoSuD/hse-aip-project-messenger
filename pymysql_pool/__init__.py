import collections
import threading
import pymysql


# Взаимствованная библиотека aiomysql переделанная под синхронное выполнение https://github.com/aio-libs/aiomysql
class _PoolAcquireContextManager:
    def __init__(self, conn, pool):
        self._pool = pool
        self._conn = conn

    def __enter__(self):
        return self._conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self._pool.release(self._conn)
        finally:
            self._pool = None
            self._conn = None


class Pool:
    def __init__(self, minsize: int = 1, maxsize: int = 10, **kwargs):
        if minsize < 0:
            raise ValueError("minsize should be zero or greater")
        if maxsize < minsize and maxsize != 0:
            raise ValueError("maxsize should be not less than minsize")

        self._minsize = minsize
        self._maxsize = maxsize
        self._conn_kwargs = kwargs
        self._free = collections.deque(maxlen=maxsize or None)
        self._cond = threading.Condition()
        self._closing = False
        self._closed = False
        self._acquiring = 0
        self._used = set()

    @property
    def size(self):
        return self.freesize + len(self._used) + self._acquiring

    @property
    def freesize(self):
        return len(self._free)

    @property
    def minsize(self):
        return self._minsize

    @property
    def maxsize(self):
        return self._free.maxlen

    def close(self):
        """Close pool.

        Mark all pool connections to be closed on getting back to pool.
        Closed pool doesn't allow to acquire new connections.
        """
        if self._closed:
            return
        self._closing = True

        while self._free:
            conn = self._free.popleft()
            conn.close()

        with self._cond:
            while self.size > self.freesize:
                self._cond.wait()

    def acquire(self):
        return _PoolAcquireContextManager(self._acquire(), self)

    def _acquire(self):
        if self._closing:
            raise RuntimeError('Cannot acquire connection after closing pool')

        with self._cond:
            while True:
                self._fill_free_pool(True)
                if self._free:
                    conn = self._free.popleft()
                    conn.ping(reconnect=True)
                    assert conn.open, conn
                    assert conn not in self._used, (conn, self._used)
                    self._used.add(conn)
                    return conn
                else:
                    self._cond.wait()

    def _fill_free_pool(self, override_min):
        # iterate over free connections and remove timed out ones
        # free_size = len(self._free)
        # n = 0
        # while n < free_size:
        #     conn = self._free[-1]
        #     if conn._reader.at_eof() or conn._reader.exception():
        #         self._free.pop()
        #         conn.close()
        #
        #     # On MySQL 8.0 a timed out connection sends an error packet before
        #     # closing the connection, preventing us from relying on at_eof().
        #     # This relies on our custom StreamReader, as eof_received is not
        #     # present in asyncio.StreamReader.
        #     elif conn._reader.eof_received:
        #         self._free.pop()
        #         conn.close()
        #
        #     elif -1 < self._recycle < time.time().time() - conn.last_usage:
        #         self._free.pop()
        #         conn.close()
        #     else:
        #         self._free.rotate()
        #     n += 1

        while self.size < self.minsize:
            self._acquiring += 1
            try:
                conn = pymysql.connect(**self._conn_kwargs)
                # raise exception if pool is closing
                self._free.append(conn)
                self._cond.notify()
            finally:
                self._acquiring -= 1
        if self._free:
            return

        if override_min and (not self.maxsize or self.size < self.maxsize):
            self._acquiring += 1
            try:
                conn = pymysql.connect(**self._conn_kwargs)
                self._free.append(conn)
                self._cond.notify()
            finally:
                self._acquiring -= 1

    def _wakeup(self):
        with self._cond:
            self._cond.notify()

    def release(self, conn):
        """Release free connection back to the connection pool."""

        assert conn in self._used, (conn, self._used)
        self._used.remove(conn)
        if conn.open:
            if self._closing:
                conn.close()
            else:
                self._free.append(conn)
            self._wakeup()
