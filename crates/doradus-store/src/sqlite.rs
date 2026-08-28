//! Small database-engine adapter used by the typed store.
//!
//! Keeping this conversion layer local prevents rusqlite types from leaking
//! into repository APIs and makes a future backend replacement mechanical.

use std::sync::Arc;

use rusqlite::types::{Type, Value, ValueRef};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SqliteValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(Arc<str>),
    Blob(Arc<[u8]>),
}

impl From<&str> for SqliteValue {
    fn from(value: &str) -> Self {
        Self::Text(Arc::from(value))
    }
}

impl From<String> for SqliteValue {
    fn from(value: String) -> Self {
        Self::Text(Arc::from(value))
    }
}

impl From<i64> for SqliteValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<&[u8]> for SqliteValue {
    fn from(value: &[u8]) -> Self {
        Self::Blob(Arc::from(value))
    }
}

impl From<Vec<u8>> for SqliteValue {
    fn from(value: Vec<u8>) -> Self {
        Self::Blob(Arc::from(value))
    }
}

impl SqliteValue {
    fn to_rusqlite_value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Integer(value) => Value::Integer(*value),
            Self::Real(value) => Value::Real(*value),
            Self::Text(value) => Value::Text(value.to_string()),
            Self::Blob(value) => Value::Blob(value.to_vec()),
        }
    }

    fn from_value_ref(index: usize, value: ValueRef<'_>) -> rusqlite::Result<Self> {
        match value {
            ValueRef::Null => Ok(Self::Null),
            ValueRef::Integer(value) => Ok(Self::Integer(value)),
            ValueRef::Real(value) => Ok(Self::Real(value)),
            ValueRef::Text(value) => String::from_utf8(value.to_vec())
                .map(|value| Self::Text(Arc::from(value)))
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(index, Type::Text, Box::new(error))
                }),
            ValueRef::Blob(value) => Ok(Self::Blob(Arc::from(value))),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Row {
    values: Vec<SqliteValue>,
}

impl Row {
    pub(crate) fn get(&self, index: usize) -> Option<&SqliteValue> {
        self.values.get(index)
    }
}

pub(crate) struct Connection {
    inner: rusqlite::Connection,
}

impl Connection {
    pub(crate) fn open(path: &str) -> rusqlite::Result<Self> {
        rusqlite::Connection::open(path).map(|inner| Self { inner })
    }

    pub(crate) fn execute(&self, sql: &str) -> rusqlite::Result<usize> {
        if sql.trim_start().to_ascii_uppercase().starts_with("PRAGMA") {
            // SQLite PRAGMAs such as journal_mode and wal_checkpoint return a
            // result row. rusqlite deliberately requires query/query_row for
            // those, while the old store adapter accepted them through its
            // generic execute method.
            self.inner.execute_batch(sql)?;
            return Ok(0);
        }
        self.inner.execute(sql, [])
    }

    pub(crate) fn execute_batch(&self, sql: &str) -> rusqlite::Result<()> {
        self.inner.execute_batch(sql)
    }

    pub(crate) fn execute_with_params(
        &self,
        sql: &str,
        params: &[SqliteValue],
    ) -> rusqlite::Result<usize> {
        let values = params
            .iter()
            .map(SqliteValue::to_rusqlite_value)
            .collect::<Vec<_>>();
        self.inner.execute(sql, rusqlite::params_from_iter(values))
    }

    pub(crate) fn query(&self, sql: &str) -> rusqlite::Result<Vec<Row>> {
        self.query_with_values(sql, rusqlite::params_from_iter(std::iter::empty::<Value>()))
    }

    pub(crate) fn query_with_params(
        &self,
        sql: &str,
        params: &[SqliteValue],
    ) -> rusqlite::Result<Vec<Row>> {
        let values = params
            .iter()
            .map(SqliteValue::to_rusqlite_value)
            .collect::<Vec<_>>();
        self.query_with_values(sql, rusqlite::params_from_iter(values))
    }

    fn query_with_values<I>(&self, sql: &str, params: I) -> rusqlite::Result<Vec<Row>>
    where
        I: rusqlite::Params,
    {
        let mut statement = self.inner.prepare(sql)?;
        let column_count = statement.column_count();
        let rows = statement.query_map(params, |row| {
            let mut values = Vec::with_capacity(column_count);
            for index in 0..column_count {
                values.push(SqliteValue::from_value_ref(index, row.get_ref(index)?)?);
            }
            Ok(Row { values })
        })?;
        rows.collect()
    }

    pub(crate) fn close(self) -> rusqlite::Result<()> {
        match self.inner.close() {
            Ok(()) => Ok(()),
            Err((_connection, error)) => Err(error),
        }
    }

    #[cfg(test)]
    pub(crate) fn close_without_checkpoint(self) -> rusqlite::Result<()> {
        drop(self);
        Ok(())
    }
}
