################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2024 QuestDB
##
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##
##  http://www.apache.org/licenses/LICENSE-2.0
##
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.
##
################################################################################

__all__ = [
    "Buffer",
    "IngressError",
    "IngressErrorCode",
    "IngressServerRejectionError",
    "Protocol",
    "Sender",
    "QwpWsError",
    "QwpWsErrorCategory",
    "QwpWsErrorPolicy",
    "QwpWsProgress",
    "ServerTimestampType",
    "TimestampMicros",
    "TimestampNanos",
    "TlsCa",
]

from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union

import numpy as np
import pandas as pd
from decimal import Decimal

class IngressErrorCode(Enum):
    """Category of Error."""

    CouldNotResolveAddr = ...
    InvalidApiCall = ...
    SocketError = ...
    InvalidUtf8 = ...
    InvalidName = ...
    InvalidTimestamp = ...
    AuthError = ...
    TlsError = ...
    HttpNotSupported = ...
    ServerFlushError = ...
    ServerRejection = ...
    ConfigError = ...
    ArrayError = ...
    ProtocolVersionError = ...
    DecimalError = ...
    BadDataFrame = ...


class IngressError(Exception):
    """An error whilst using the ``Sender`` or constructing its ``Buffer``."""

    @property
    def code(self) -> IngressErrorCode:
        """Return the error code."""

    @property
    def qwp_ws_error(self) -> Optional["QwpWsError"]:
        """
        Return the structured QWP/WebSocket HALT diagnostic, if this error
        carries one from a terminal QWP/WebSocket sender failure.
        """


class IngressServerRejectionError(IngressError):
    """
    A terminal QWP/WebSocket server rejection.

    The structured server payload is available through
    :attr:`IngressError.qwp_ws_error`.
    """


class ServerTimestampType:
    """
    A placeholder value to indicate using a server-generated-timestamp.
    """


class TimestampMicros:
    """
    A timestamp in microseconds since the UNIX epoch (UTC).

    You may construct a ``TimestampMicros`` from an integer or a
    ``datetime.datetime``, or simply call the :func:`TimestampMicros.now`
    method.

    .. code-block:: python

        # Recommended way to get the current timestamp.
        TimestampMicros.now()

        # The above is equivalent to:
        TimestampMicros(time.time_ns() // 1000)

        # You can provide a numeric timestamp too. It can't be negative.
        TimestampMicros(1657888365426838)

    ``TimestampMicros`` can also be constructed from a ``datetime.datetime``
    object.

    .. code-block:: python

        TimestampMicros.from_datetime(
            datetime.datetime.now(tz=datetime.timezone.utc))

    We recommend that when using ``datetime`` objects, you explicitly pass in
    the timezone to use. This is because ``datetime`` objects without an
    associated timezone are assumed to be in the local timezone and it is easy
    to make mistakes (e.g. passing ``datetime.datetime.utcnow()`` is a likely
    bug).
    """

    def __init__(self, value: int): ...
    @classmethod
    def from_datetime(cls, dt: datetime) -> TimestampMicros:
        """
        Construct a ``TimestampMicros`` from a ``datetime.datetime`` object.
        """

    @classmethod
    def now(cls) -> TimestampMicros:
        """
        Construct a ``TimestampMicros`` from the current time as UTC.
        """

    @property
    def value(self) -> int:
        """Number of microseconds (Unix epoch timestamp, UTC)."""


class TimestampNanos:
    """
    A timestamp in nanoseconds since the UNIX epoch (UTC).

    You may construct a ``TimestampNanos`` from an integer or a
    ``datetime.datetime``, or simply call the :func:`TimestampNanos.now`
    method.

    .. code-block:: python

        # Recommended way to get the current timestamp.
        TimestampNanos.now()

        # The above is equivalent to:
        TimestampNanos(time.time_ns())

        # You can provide a numeric timestamp too. It can't be negative.
        TimestampNanos(1657888365426838016)

    ``TimestampNanos`` can also be constructed from a ``datetime`` object.

    .. code-block:: python

        TimestampNanos.from_datetime(
            datetime.datetime.now(tz=datetime.timezone.utc))

    We recommend that when using ``datetime`` objects, you explicitly pass in
    the timezone to use. This is because ``datetime`` objects without an
    associated timezone are assumed to be in the local timezone and it is easy
    to make mistakes (e.g. passing ``datetime.datetime.utcnow()`` is a likely
    bug).
    """

    def __init__(self, value: int): ...
    @classmethod
    def from_datetime(cls, dt: datetime) -> TimestampNanos:
        """
        Construct a ``TimestampNanos`` from a ``datetime.datetime`` object.
        """

    @classmethod
    def now(cls) -> TimestampNanos:
        """
        Construct a ``TimestampNanos`` from the current time as UTC.
        """

    @property
    def value(self) -> int:
        """Number of nanoseconds (Unix epoch timestamp, UTC)."""

class SenderTransaction:
    """
    A transaction for a specific table.

    Transactions are not supported with ILP/TCP, only ILP/HTTP.

    The sender API can only operate on one transaction at a time.

    To create a transaction:

    .. code-block:: python

        with sender.transaction('table_name') as txn:
            txn.row(..)
            txn.dataframe(..)
    """

    def __init__(self, sender: Sender, table_name: str): ...
    def __enter__(self) -> SenderTransaction: ...
    def __exit__(self, exc_type, _exc_value, _traceback) -> bool: ...
    def row(
        self,
        *,
        symbols: Optional[Dict[str, Optional[str]]] = None,
        columns: Optional[
            Dict[str, Union[None, bool, int, float, str, TimestampMicros, datetime, np.ndarray, Decimal]]
        ] = None,
        at: Union[ServerTimestampType, TimestampNanos, datetime],
    ) -> SenderTransaction:
        """
        Write a row for the table in the transaction.

        The table name is taken from the transaction.

        **Note**: Support for NumPy arrays (``np.array``) requires QuestDB server version 9.0.0 or higher.
        """

    def dataframe(
        self,
        df: pd.DataFrame,
        *,
        symbols: Union[str, bool, List[int], List[str]] = "auto",
        at: Union[ServerTimestampType, int, str, TimestampNanos, datetime],
    ) -> SenderTransaction:
        """
        Write a dataframe for the table in the transaction.

        The table name is taken from the transaction.
        """

    def commit(self):
        """
        Commit the transaction.

        A commit is also automatic at the end of a successful `with` block.

        This will flush the buffer.
        """

    def rollback(self):
        """
        Roll back the transaction.

        A rollback is also automatic at the end of a failed `with` block.

        This will clear the buffer.
        """


class Buffer:
    """
    Buffer for serializing rows before flushing through a
    :func:`Sender <questdb.ingress.Sender>`.

    Use the factory class methods to create a buffer:

    * :func:`Buffer.ilp` for ILP (InfluxDB Line Protocol) buffers.
    * :func:`Buffer.qwp` for QWP (QuestWire Protocol) buffers.

    .. code-block:: python

        from questdb.ingress import Buffer, Sender, Protocol, TimestampNanos

        buf = Buffer.ilp(protocol_version=2)
        buf.row(
            'table_name',
            symbols={'s1': 'v1'},
            columns={'c1': True, 'c2': 0.5},
            at=TimestampNanos.now())

        with Sender(Protocol.Http, 'localhost', 9000) as sender:
            sender.flush(buf)

    Alternatively, call :func:`Sender.new_buffer` which creates the
    correct buffer type (ILP or QWP) matching the sender's protocol.

    """

    def __init__(
            self,
            protocol_version: int,
            init_buf_size: int = 65536,
            max_name_len: int = 127):
        """
        .. deprecated::
            Use :func:`Buffer.ilp` or :func:`Buffer.qwp` instead.
        """
        ...

    @staticmethod
    def ilp(
            protocol_version: int = 2,
            init_buf_size: int = 65536,
            max_name_len: int = 127) -> Buffer:
        """
        Create an ILP (InfluxDB Line Protocol) buffer.

        :param int protocol_version: The protocol version to use (1-3).
        :param int init_buf_size: Initial capacity of the buffer in bytes.
        :param int max_name_len: Maximum length of a table or column name.
        """
        ...

    @staticmethod
    def qwp(
            init_buf_size: int = 65536,
            max_name_len: int = 127) -> Buffer:
        """
        Create a QWP (QuestWire Protocol) buffer.

        :param int init_buf_size: Initial capacity of the buffer in bytes.
        :param int max_name_len: Maximum length of a table or column name.
        """
        ...

    @property
    def init_buf_size(self) -> int:
        """
        The initial capacity of the buffer when first created.

        This may grow over time, see ``capacity()``.
        """

    @property
    def max_name_len(self) -> int:
        """Maximum length of a table or column name."""

    def reserve(self, additional: int):
        """
        Ensure the buffer has at least `additional` bytes of future capacity.

        :param int additional: Additional bytes to reserve.
        """

    def capacity(self) -> int:
        """The current buffer capacity."""

    def clear(self):
        """
        Reset the buffer.

        Note that flushing a buffer will (unless otherwise specified)
        also automatically clear it.

        This method is designed to be called only in conjunction with
        ``sender.flush(buffer, clear=False)``.
        """

    def __len__(self) -> int:
        """
        The current number of bytes currently in the buffer.

        Equivalent (but cheaper) to ``len(bytes(buffer))``.
        """

    def  __bytes__(self) -> bytes:
        """Return the constructed buffer as bytes. Use for debugging."""

    def row(
        self,
        table_name: str,
        *,
        symbols: Optional[Dict[str, Optional[str]]] = None,
        columns: Optional[
            Dict[str, Union[None, bool, int, float, str, TimestampMicros, datetime, np.ndarray, Decimal]]
        ] = None,
        at: Union[ServerTimestampType, TimestampNanos, datetime],
    ) -> Buffer:
        """
        Add a single row (line) to the buffer.

        .. code-block:: python

            # All fields specified.
            buffer.row(
                'table_name',
                symbols={'sym1': 'abc', 'sym2': 'def', 'sym3': None},
                columns={
                    'col1': True,
                    'col2': 123,
                    'col3': 3.14,
                    'col4': 'xyz',
                    'col5': TimestampMicros(123456789),
                    'col6': datetime(2019, 1, 1, 12, 0, 0),
                    'col7': np.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]),
                    'col8': None,
                    'col9': Decimal('123.456')},
                at=TimestampNanos(123456789))

            # Only symbols specified. Designated timestamp assigned by the db.
            buffer.row(
                'table_name',
                symbols={'sym1': 'abc', 'sym2': 'def'}, at=Server.Timestamp)

            # Float columns and timestamp specified as `datetime.datetime`.
            # Pay special attention to the timezone, which if unspecified is
            # assumed to be the local timezone (and not UTC).
            buffer.row(
                'sensor data',
                columns={
                    'temperature': 24.5,
                    'humidity': 0.5},
                at=datetime.datetime.now(tz=datetime.timezone.utc))


        Python strings passed as values to ``symbols`` are going to be encoded
        as the ``SYMBOL`` type in QuestDB, whilst Python strings passed as
        values to ``columns`` are going to be encoded as the ``STRING`` type.

        Refer to the
        `QuestDB documentation <https://questdb.com/docs/concept/symbol/>`_ to
        understand the difference between the ``SYMBOL`` and ``STRING`` types
        (TL;DR: symbols are interned strings).

        Column values can be specified with Python types directly and map as so:

        .. list-table::
            :header-rows: 1

            * - Python type
              - Serialized as ILP type
            * - ``bool``
              - `BOOLEAN <https://questdb.com/docs/reference/api/ilp/columnset-types#boolean>`_
            * - ``int``
              - `INTEGER <https://questdb.com/docs/reference/api/ilp/columnset-types#integer>`_
            * - ``float``
              - `FLOAT <https://questdb.com/docs/reference/api/ilp/columnset-types#float>`_
            * - ``str``
              - `STRING <https://questdb.com/docs/reference/api/ilp/columnset-types#string>`_
            * - ``np.ndarray``
              - `ARRAY <https://questdb.com/docs/reference/api/ilp/columnset-types#array>`_
            * - ``datetime.datetime`` and ``TimestampMicros``
              - `TIMESTAMP <https://questdb.com/docs/reference/api/ilp/columnset-types#timestamp>`_
            * - ``Decimal``
              - `DECIMAL <https://questdb.com/docs/reference/api/ilp/columnset-types#decimal>`_
            * - ``None``
              - *Column is skipped and not serialized.*

        **Note**: Support for NumPy arrays (``np.array``) requires QuestDB server version 9.0.0 or higher.

        If the destination table was already created, then the columns types
        will be cast to the types of the existing columns whenever possible
        (Refer to the QuestDB documentation pages linked above).

        Adding a row can trigger auto-flushing behaviour.

        :param table_name: The name of the table to which the row belongs.
        :param symbols: A dictionary of symbol column names to ``str`` values.
            As a convenience, you can also pass a ``None`` value which will
            have the same effect as skipping the key: If the column already
            existed, it will be recorded as ``NULL``, otherwise it will not be
            created.
        :param columns: A dictionary of column names to ``bool``, ``int``,
            ``float``, ``str``, ``TimestampMicros`` or ``datetime`` values.
            As a convenience, you can also pass a ``None`` value which will
            have the same effect as skipping the key: If the column already
            existed, it will be recorded as ``NULL``, otherwise it will not be
            created.
        :param at: The timestamp of the row. This is required!
            If ``ServerTimestamp``, timestamp is assigned by QuestDB.
            If ``datetime``, the timestamp is converted to nanoseconds.
            A nanosecond unix epoch timestamp can be passed
            explicitly as a ``TimestampNanos`` object.
        """

    def dataframe(
        self,
        df: pd.DataFrame,
        *,
        table_name: Optional[str] = None,
        table_name_col: Union[None, int, str] = None,
        symbols: Union[str, bool, List[int], List[str]] = "auto",
        at: Union[ServerTimestampType, int, str, TimestampNanos, datetime],
    ) -> Buffer:
        """
        Add a pandas DataFrame to the buffer.

        Also see the :func:`Sender.dataframe` method if you're
        not using the buffer explicitly. It supports the same parameters
        and also supports auto-flushing.

        This feature requires the ``pandas``, ``numpy`` and ``pyarrow``
        package to be installed.

        Adding a dataframe can trigger auto-flushing behaviour,
        even between rows of the same dataframe. To avoid this, you can
        use HTTP and transactions (see :func:`Sender.transaction`).

        :param df: The pandas DataFrame to serialize to the buffer.
        :type df: pandas.DataFrame

        :param table_name: The name of the table to which the rows belong.

            If ``None``, the table name is taken from the ``table_name_col``
            parameter. If both ``table_name`` and ``table_name_col`` are
            ``None``, the table name is taken from the DataFrame's index
            name (``df.index.name`` attribute).
        :type table_name: str or None

        :param table_name_col: The name or index of the column in the DataFrame
            that contains the table name.

            If ``None``, the table name is taken
            from the ``table_name`` parameter. If both ``table_name`` and
            ``table_name_col`` are ``None``, the table name is taken from the
            DataFrame's index name (``df.index.name`` attribute).

            If ``table_name_col`` is an integer, it is interpreted as the index
            of the column starting from ``0``. The index of the column can be
            negative, in which case it is interpreted as an offset from the end
            of the DataFrame. E.g. ``-1`` is the last column.
        :type table_name_col: str or int or None

        :param symbols: The columns to be serialized as symbols.

            If ``'auto'`` (default), all columns of dtype ``'categorical'`` are
            serialized as symbols. If ``True``, all ``str`` columns are
            serialized as symbols. If ``False``, no columns are serialized as
            symbols.

            The list of symbols can also be specified explicitly as a ``list``
            of column names (``str``) or indices (``int``). Integer indices
            start at ``0`` and can be negative, offset from the end of the
            DataFrame. E.g. ``-1`` is the last column.

            Only columns containing strings can be serialized as symbols.

        :type symbols: str or bool or list[str] or list[int]

        :param at: The designated timestamp of the rows.

            You can specify a single value for all rows or column name or index.
            If ``ServerTimestamp``, timestamp is assigned by the server for all rows.
            To pass in a timestamp explicitly as an integer use the
            ``TimestampNanos`` wrapper type. To get the current timestamp,
            use ``TimestampNanos.now()``.
            When passing a ``datetime.datetime`` object, the timestamp is
            converted to nanoseconds.
            A ``datetime`` object is assumed to be in the local timezone unless
            one is specified explicitly (so call
            ``datetime.datetime.now(tz=datetime.timezone.utc)`` instead
            of ``datetime.datetime.utcnow()`` for the current timestamp to
            avoid bugs).

            To specify a different timestamp for each row, pass in a column name
            (``str``) or index (``int``, 0-based index, negative index
            supported): In this case, the column needs to be of dtype
            ``datetime64[ns]`` (assumed to be in the **UTC timezone** and not
            local, due to differences in Pandas and Python datetime handling) or
            ``datetime64[ns, tz]``. When a timezone is specified in the column,
            it is converted to UTC automatically.

            A timestamp column can also contain ``None`` values. The server will
            assign the current timestamp to those rows.

            **Note**: All timestamps are always converted to nanoseconds and in
            the UTC timezone. Timezone information is dropped before sending and
            QuestDB will not store any timezone information.
        :type at: TimestampNanos, datetime.datetime, int or str or None

        **Note**: It is an error to specify both ``table_name`` and
        ``table_name_col``.

        **Note**: The "index" column of the DataFrame is never serialized,
        even if it is named.

        Example:

        .. code-block:: python

            import pandas as pd
            import questdb.ingress as qi

            buf = qi.Buffer.ilp(protocol_version=2)
            # ...

            df = pd.DataFrame({
                'location': ['London', 'Managua', 'London'],
                'temperature': [24.5, 35.0, 25.5],
                'humidity': [0.5, 0.6, 0.45],
                'ts': pd.date_range('2021-07-01', periods=3)})
            buf.dataframe(
                df, table_name='weather', at='ts', symbols=['location'])

            # ...
            sender.flush(buf)

        **Pandas to ILP datatype mappings**

        .. seealso:: https://questdb.com/docs/reference/api/ilp/columnset-types/

        .. list-table:: Pandas Mappings
            :header-rows: 1

            * - Pandas ``dtype``
              - Nulls
              - ILP Datatype
            * - ``'bool'``
              - N
              - ``BOOLEAN``
            * - ``'boolean'``
              - N **α**
              - ``BOOLEAN``
            * - ``'object'`` (``bool`` objects)
              - N **α**
              - ``BOOLEAN``
            * - ``'uint8'``
              - N
              - ``INTEGER``
            * - ``'int8'``
              - N
              - ``INTEGER``
            * - ``'uint16'``
              - N
              - ``INTEGER``
            * - ``'int16'``
              - N
              - ``INTEGER``
            * - ``'uint32'``
              - N
              - ``INTEGER``
            * - ``'int32'``
              - N
              - ``INTEGER``
            * - ``'uint64'``
              - N
              - ``INTEGER`` **β**
            * - ``'int64'``
              - N
              - ``INTEGER``
            * - ``'UInt8'``
              - Y
              - ``INTEGER``
            * - ``'Int8'``
              - Y
              - ``INTEGER``
            * - ``'UInt16'``
              - Y
              - ``INTEGER``
            * - ``'Int16'``
              - Y
              - ``INTEGER``
            * - ``'UInt32'``
              - Y
              - ``INTEGER``
            * - ``'Int32'``
              - Y
              - ``INTEGER``
            * - ``'UInt64'``
              - Y
              - ``INTEGER`` **β**
            * - ``'Int64'``
              - Y
              - ``INTEGER``
            * - ``'object'`` (``int`` objects)
              - Y
              - ``INTEGER`` **β**
            * - ``'float32'`` **γ**
              - Y (``NaN``)
              - ``FLOAT``
            * - ``'float64'``
              - Y (``NaN``)
              - ``FLOAT``
            * - ``'object'`` (``float`` objects)
              - Y (``NaN``)
              - ``FLOAT``
            * - ``'string'`` (``str`` objects)
              - Y
              - ``STRING`` (default), ``SYMBOL`` via ``symbols`` arg. **δ**
            * - ``'string[pyarrow]'``
              - Y
              - ``STRING`` (default), ``SYMBOL`` via ``symbols`` arg. **δ**
            * - ``'category'`` (``str`` objects) **ε**
              - Y
              - ``SYMBOL`` (default), ``STRING`` via ``symbols`` arg. **δ**
            * - ``'object'`` (``str`` objects)
              - Y
              - ``STRING`` (default), ``SYMBOL`` via ``symbols`` arg. **δ**
            * - ``'object' (``numpy.ndarray[numpy.float64]``)``
              - Y
              - ``ARRAY[DOUBLE]``
            * - ``'datetime64[ns]'``
              - Y
              - ``TIMESTAMP`` **ζ**
            * - ``'datetime64[ns, tz]'``
              - Y
              - ``TIMESTAMP`` **ζ**
            * - ``'object'`` (``Decimal`` objects)
              - Y (``NaN``)
              - ``DECIMAL``

        .. note::

            * **α**: Note some pandas dtypes allow nulls (e.g. ``'boolean'``),
              where the QuestDB database does not.

            * **β**: The valid range for integer values is -2^63 to 2^63-1.
              Any ``'uint64'``, ``'UInt64'`` or python ``int`` object values
              outside this range will raise an error during serialization.

            * **γ**: Upcast to 64-bit float during serialization.

            * **δ**: Columns containing strings can also be used to specify the
              table name. See ``table_name_col``.

            * **ε**: We only support categories containing strings. If the
              category contains non-string values, an error will be raised.

            * **ζ**: The '.dataframe()' method only supports datetimes with
              nanosecond precision. The designated timestamp column (see ``at``
              parameter) maintains the nanosecond precision, whilst values
              stored as columns have their precision truncated to microseconds.
              All dates are sent as UTC and any additional timezone information
              is dropped. If no timezone is specified, we follow
              the pandas convention of assuming the timezone is UTC.
              Datetimes before 1970-01-01 00:00:00 UTC are not supported.
              If a datetime value is specified as ``None`` (``NaT``), it is
              interpreted as the current QuestDB server time set on receipt of
              message.

            * **η**: Support for NumPy arrays (``np.array``) requires QuestDB
              server version 9.0.0 or higher.

        **Error Handling and Recovery**

        In case an exception is raised during dataframe serialization, the
        buffer is left in its previous state.
        The buffer remains in a valid state and can be used for further calls
        even after an error.

        For clarification, as an example, if an invalid ``None``
        value appears at the 3rd row for a ``bool`` column, neither the 3rd nor
        the preceding rows are added to the buffer.

        **Note**: This differs from the :func:`Sender.dataframe` method, which
        modifies this guarantee due to its ``auto_flush`` logic.

        **Performance Considerations**

        The Python GIL is released during serialization if it is not needed.
        If any column requires the GIL, the entire serialization is done whilst
        holding the GIL.

        Column types that require the GIL are:

        * Columns of ``str``, ``float`` or ``int`` or ``float`` Python objects.
        * The ``'string[python]'`` dtype.
        """

class TaggedEnum(Enum):
    """
    Base class for tagged enums.
    """

    @property
    def tag(self) -> str:
        """
        Short name.
        """

    @property
    def c_value(self) -> Any: ...
    @classmethod
    def parse(cls, tag) -> TaggedEnum:
        """
        Parse from the tag name.
        """

class Protocol(TaggedEnum):
    """
    Protocol to use for sending data to QuestDB.

    See :ref:`sender_which_protocol` for more information.
    """

    Tcp = ...
    Tcps = ...
    Http = ...
    Https = ...
    QwpUdp = ...
    QwpWs = ...
    QwpWss = ...

    @property
    def tls_enabled(self) -> bool: ...

class QwpWsProgress(TaggedEnum):
    """
    Progress mode for QWP/WebSocket senders.
    """

    Background = ...
    Manual = ...

class QwpWsErrorCategory(TaggedEnum):
    """
    Category of a structured QWP/WebSocket diagnostic.
    """

    SchemaMismatch = ...
    ParseError = ...
    InternalError = ...
    SecurityError = ...
    WriteError = ...
    ProtocolViolation = ...
    Unknown = ...

class QwpWsErrorPolicy(TaggedEnum):
    """
    Applied policy for a structured QWP/WebSocket diagnostic.
    """

    DropAndContinue = ...
    Halt = ...

@dataclass(frozen=True)
class QwpWsError:
    """
    Structured QWP/WebSocket diagnostic.
    """

    category: QwpWsErrorCategory
    applied_policy: QwpWsErrorPolicy
    status: Optional[int]
    message: str
    message_sequence: Optional[int]
    from_fsn: int
    to_fsn: int

class TlsCa(TaggedEnum):
    """
    Verification mechanism for the server's certificate.

    Here ``webpki`` refers to the
    `WebPKI library <https://github.com/rustls/webpki-roots>`_ and
    ``os`` refers to the operating system's certificate store.

    See :ref:`sender_conf_tls` for more information.
    """

    WebpkiRoots = ...
    OsRoots = ...
    WebpkiAndOsRoots = ...
    PemFile = ...

class Sender:
    """
    Ingest data into QuestDB.

    See the :ref:`sender` documentation for more information.
    """

    def __init__(
        self,
        protocol: Protocol,
        host: str,
        port: Union[int, str],
        *,
        bind_interface: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        token_x: Optional[str] = None,
        token_y: Optional[str] = None,
        auth_timeout: int = 15000,
        tls_verify: bool = True,
        tls_ca: TlsCa = TlsCa.WebpkiRoots,
        tls_roots=None,
        tls_roots_password: Optional[str] = None,
        max_buf_size: int = 104857600,
        retry_timeout: int = 10000,
        retry_max_backoff: int = 1000,
        request_min_throughput: int = 102400,
        request_timeout=None,
        auto_flush: bool = True,
        auto_flush_rows: Optional[int] = None,
        auto_flush_bytes: bool = False,
        auto_flush_interval: int = 1000,
        max_datagram_size: Optional[int] = None,
        multicast_ttl: Optional[int] = None,
        qwp_ws_progress: Optional[QwpWsProgress] = None,
        qwp_ws_error_handler: Optional[Callable[["QwpWsError"], None]] = None,
        protocol_version=None,
        init_buf_size: int = 65536,
        max_name_len: int = 127,
    ): ...
    @staticmethod
    def from_conf(
        conf_str: str,
        *,
        bind_interface: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        token_x: Optional[str] = None,
        token_y: Optional[str] = None,
        auth_timeout: int = 15000,
        tls_verify: bool = True,
        tls_ca: TlsCa = TlsCa.WebpkiRoots,
        tls_roots=None,
        tls_roots_password: Optional[str] = None,
        max_buf_size: int = 104857600,
        retry_timeout: int = 10000,
        retry_max_backoff: int = 1000,
        request_min_throughput: int = 102400,
        request_timeout=None,
        auto_flush: bool = True,
        auto_flush_rows: Optional[int] = None,
        auto_flush_bytes: bool = False,
        auto_flush_interval: int = 1000,
        max_datagram_size: Optional[int] = None,
        multicast_ttl: Optional[int] = None,
        qwp_ws_progress: Optional[QwpWsProgress] = None,
        qwp_ws_error_handler: Optional[Callable[["QwpWsError"], None]] = None,
        protocol_version=None,
        init_buf_size: int = 65536,
        max_name_len: int = 127,
    ) -> Sender:
        """
        Construct a sender from a :ref:`configuration string <sender_conf>`.

        The additional arguments are used to specify additional parameters
        which are not present in the configuration string.

        Note that any parameters already present in the configuration string
        cannot be overridden.
        """
        ...

    @staticmethod
    def from_env(
        *,
        bind_interface: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        token: Optional[str] = None,
        token_x: Optional[str] = None,
        token_y: Optional[str] = None,
        auth_timeout: int = 15000,
        tls_verify: bool = True,
        tls_ca: TlsCa = TlsCa.WebpkiRoots,
        tls_roots=None,
        tls_roots_password: Optional[str] = None,
        max_buf_size: int = 104857600,
        retry_timeout: int = 10000,
        retry_max_backoff: int = 1000,
        request_min_throughput: int = 102400,
        request_timeout=None,
        auto_flush: bool = True,
        auto_flush_rows: Optional[int] = None,
        auto_flush_bytes: bool = False,
        auto_flush_interval: int = 1000,
        max_datagram_size: Optional[int] = None,
        multicast_ttl: Optional[int] = None,
        qwp_ws_progress: Optional[QwpWsProgress] = None,
        qwp_ws_error_handler: Optional[Callable[["QwpWsError"], None]] = None,
        protocol_version=None,
        init_buf_size: int = 65536,
        max_name_len: int = 127,
    ) -> Sender:
        """
        Construct a sender from the ``QDB_CLIENT_CONF`` environment variable.

        The environment variable must be set to a valid
        :ref:`configuration string <sender_conf>`.

        The additional arguments are used to specify additional parameters
        which are not present in the configuration string.

        Note that any parameters already present in the configuration string
        cannot be overridden.
        """

    def new_buffer(self) -> Buffer:
        """
        Make a new configured buffer.

        The buffer is set up with the configured `init_buf_size` and
        `max_name_len`.
        """

    @property
    def init_buf_size(self) -> int:
        """The initial capacity of the sender's internal buffer."""

    @property
    def max_name_len(self) -> int:
        """Maximum length of a table or column name."""

    @property
    def auto_flush(self) -> bool:
        """
        Auto-flushing is enabled.

        Consult the `.auto_flush_rows`, `.auto_flush_bytes` and
        `.auto_flush_interval` properties for the current active thresholds.
        """

    @property
    def auto_flush_rows(self) -> Optional[int]:
        """
        Row count threshold for the auto-flush logic, or None if disabled.
        """

    @property
    def auto_flush_bytes(self) -> Optional[int]:
        """
        Byte-count threshold for the auto-flush logic, or None if disabled.
        """

    @property
    def auto_flush_interval(self) -> Optional[timedelta]:
        """
        Time interval threshold for the auto-flush logic, or None if disabled.
        """

    @property
    def protocol_version(self) -> int:
        """
        The protocol version used by the sender.

        Protocol version 1 is retained for backwards compatibility with
        older QuestDB versions.

        Protocol version 2 introduces binary floating point support and
        the array datatype.
        """

    @property
    def max_name_len(self):
        """
        Returns the sender's maximum-configured maximum name length for table
        names and column names.
        """

    def establish(self):
        """
        Prepare the sender for use.

        If using ILP/HTTP this will initialize the HTTP connection pool.

        If using ILP/TCP this will cause connection to the server and
        block until the connection is established.

        If the TCP connection is set up with authentication and/or TLS, this
        method will return only *after* the handshake(s) is/are complete.
        """

    def __enter__(self) -> Sender:
        """Call :func:`Sender.establish` at the start of a ``with`` block."""

    def __len__(self) -> int:
        """
        Number of bytes of unsent data in the internal buffer.

        Equivalent (but cheaper) to ``len(bytes(sender))``.
        """

    def __bytes__(self) -> bytes:
        """
        Inspect the contents of the internal buffer.

        The ``bytes`` value returned represents the unsent data.

        Also see :func:`Sender.__len__`.
        """

    def transaction(self, table_name: str) -> SenderTransaction:
        """
        Start a :ref:`sender_transaction` block.
        """

    def row(
        self,
        table_name: str,
        *,
        symbols: Optional[Dict[str, str]] = None,
        columns: Optional[
            Dict[str, Union[None, bool, int, float, str, TimestampMicros, datetime, np.ndarray]]
        ] = None,
        at: Union[TimestampNanos, datetime, ServerTimestampType],
    ) -> Sender:
        """
        Write a row to the internal buffer.

        This may be sent automatically depending on the ``auto_flush`` setting
        in the constructor.

        Refer to the :func:`Buffer.row` documentation for details on arguments.

        **Note**: Support for NumPy arrays (``np.array``) requires QuestDB server version 9.0.0 or higher.
        """

    def dataframe(
        self,
        df: pd.DataFrame,
        *,
        table_name: Optional[str] = None,
        table_name_col: Union[None, int, str] = None,
        symbols: Union[str, bool, List[int], List[str]] = "auto",
        at: Union[ServerTimestampType, int, str, TimestampNanos, datetime],
    ) -> Sender:
        """
        Write a Pandas DataFrame to the internal buffer.

        Example:

        .. code-block:: python

            import pandas as pd
            import questdb.ingress as qi

            df = pd.DataFrame({
                'car': pd.Categorical(['Nic 42', 'Eddi', 'Nic 42', 'Eddi']),
                'position': [1, 2, 1, 2],
                'speed': [89.3, 98.2, 3, 4],
                'lat_gforce': [0.1, -0.2, -0.6, 0.4],
                'accelleration': [0.1, -0.2, 0.6, 4.4],
                'tyre_pressure': [2.6, 2.5, 2.6, 2.5],
                'ts': [
                    pd.Timestamp('2022-08-09 13:56:00'),
                    pd.Timestamp('2022-08-09 13:56:01'),
                    pd.Timestamp('2022-08-09 13:56:02'),
                    pd.Timestamp('2022-08-09 13:56:03')]})

            with qi.Sender.from_env() as sender:
                sender.dataframe(df, table_name='race_metrics', at='ts')

        This method builds on top of the :func:`Buffer.dataframe` method.
        See its documentation for details on arguments.

        Additionally, this method also supports auto-flushing the buffer
        as specified in the ``Sender``'s ``auto_flush`` constructor argument.
        Auto-flushing is implemented incrementally, meanting that when
        calling ``sender.dataframe(df)`` with a large ``df``, the sender may
        have sent some of the rows to the server already whist the rest of the
        rows are going to be sent at the next auto-flush or next explicit call
        to :func:`Sender.flush`.

        In case of data errors with auto-flushing enabled, some of the rows
        may have been transmitted to the server already.
        """

    def flush(
        self,
        buffer: Optional[Buffer] = None,
        clear: bool = True,
        transactional: bool = False,
    ):
        """
        If called with no arguments, immediately flushes the internal buffer.

        Alternatively you can flush a buffer that was constructed explicitly
        by passing ``buffer``.

        The buffer will be cleared by default, unless ``clear`` is set to
        ``False``.

        This method does nothing if the provided or internal buffer is empty.

        :param buffer: The buffer to flush. If ``None``, the internal buffer
            is flushed.

        With QWP/WebSocket, this publishes the buffer into the local sender
        queue and returns before the server necessarily ACKs the frame. Later
        terminal diagnostics fail subsequent sender calls and are available as
        :attr:`IngressError.qwp_ws_error`. Server diagnostics are also
        available through :func:`Sender.poll_qwp_ws_error`.

        :param clear: If ``True``, the flushed buffer is cleared (default).
            If ``False``, the flushed buffer is left in the internal buffer.
            Note that ``clear=False`` is only supported if ``buffer`` is also
            specified.

        :param transactional: If ``True`` ensures that the flushed buffer
            contains row for a single table, ensuring all data can be written
            transactionally. This feature requires ILP/HTTP and is not available
            when connecting over TCP. *Default: False.*

        The Python GIL is released during the network IO operation.
        """

    def flush_and_get_fsn(self, buffer: Optional[Buffer] = None) -> Optional[int]:
        """
        Publish a QWP/WebSocket buffer locally, clear it on success, and return
        the assigned frame sequence number.
        """

    def flush_and_keep_and_get_fsn(
        self, buffer: Optional[Buffer] = None
    ) -> Optional[int]:
        """
        Publish a QWP/WebSocket buffer locally without clearing it and return
        the assigned frame sequence number.
        """

    def published_fsn(self) -> Optional[int]:
        """
        Highest QWP/WebSocket frame sequence number published locally.
        """

    def acked_fsn(self) -> Optional[int]:
        """
        Highest QWP/WebSocket frame sequence number completed by ACK or
        drop-and-continue rejection.
        """

    def await_acked_fsn(self, fsn: int, timeout_millis: int) -> bool:
        """
        Wait until the QWP/WebSocket completion watermark reaches ``fsn``.
        """

    def drive_once(self) -> bool:
        """
        Drive one QWP/WebSocket progress step for manual progress senders.
        """

    def poll_qwp_ws_error(self) -> Optional[QwpWsError]:
        """
        Poll the next structured QWP/WebSocket diagnostic.
        """

    def qwp_ws_errors_dropped(self) -> int:
        """
        Number of QWP/WebSocket diagnostics dropped from the bounded ring.
        """

    def close_drain(self):
        """
        Stop accepting new QWP/WebSocket publications and wait for already
        published frames to resolve.
        """

    def close(self, flush: bool = True):
        """
        Disconnect.

        This method is idempotent and can be called repeatedly.

        Once a sender is closed, it can't be re-used.

        :param bool flush: If ``True``, flush the internal buffer before closing.
            For QWP/WebSocket, this also drains already-published frames before
            closing.
        """

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        """
        Flush pending and disconnect at the end of a ``with`` block.

        If the ``with`` block raises an exception, any pending data will
        *NOT* be flushed.

        This is implemented by calling :func:`Sender.close`.
        """
