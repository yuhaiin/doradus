use super::*;

pub fn json_value_is_go_zero(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(value) => !value,
        Value::Number(value) => {
            value.as_i64() == Some(0) || value.as_u64() == Some(0) || value.as_f64() == Some(0.0)
        }
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
    }
}

pub fn rename_json_field(object: &mut serde_json::Map<String, Value>, legacy: &str, public: &str) {
    if object.contains_key(public) {
        object.remove(legacy);
    } else if let Some(value) = object.remove(legacy) {
        object.insert(public.to_owned(), value);
    }
}

pub fn required_string(value: &Value, key: &str) -> std::result::Result<String, ApiError> {
    string_or_opt(value, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad(format!("{key} is required")))
}

pub fn go_request_string(value: &Value, key: &str) -> std::result::Result<String, ApiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(ApiError::bad(format!("{key} must be a string"))),
    }
}

pub fn string_or(value: &Value, key: &str, default: &str) -> String {
    string_or_opt(value, key).unwrap_or_else(|| default.to_owned())
}

pub fn string_or_any(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| string_or_opt(value, key))
        .unwrap_or_default()
}

pub fn string_or_opt(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

pub fn bool_or(value: &Value, key: &str, default: bool) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(default)
}

pub fn bool_or_any(value: &Value, keys: &[&str], default: bool) -> bool {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
        .unwrap_or(default)
}

pub fn number(value: &Value, key: &str) -> std::result::Result<usize, ApiError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .ok_or_else(|| ApiError::bad(format!("{key} must be a non-negative integer")))
}

pub fn go_request_number(value: &Value, key: &str) -> std::result::Result<usize, ApiError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(|value| value as usize)
            .ok_or_else(|| ApiError::bad(format!("{key} must be a non-negative integer"))),
        Some(_) => Err(ApiError::bad(format!(
            "{key} must be a non-negative integer"
        ))),
    }
}

pub fn set_string(value: &mut Value, key: &str, text: impl Into<String>) {
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_owned(), Value::String(text.into()));
    }
}

pub fn set_bool(value: &mut Value, key: &str, flag: bool) {
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_owned(), Value::Bool(flag));
    }
}

pub fn object_or_fallback(bytes: &[u8], fallback: Value) -> Value {
    raw_json(bytes, fallback)
}

pub fn raw_json(bytes: &[u8], fallback: Value) -> Value {
    serde_json::from_slice(bytes).unwrap_or(fallback)
}

pub fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

pub fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(i64::MAX as u128) as i64
        })
}

pub fn json_value(value: Value) -> ApiResult {
    Ok(Json(value))
}

pub fn empty_json() -> Json<Value> {
    Json(json!({}))
}

pub fn empty() -> ApiResult {
    Ok(empty_json())
}
