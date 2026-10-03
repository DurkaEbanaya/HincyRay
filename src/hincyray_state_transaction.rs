//! Three-way rollback: undo this operation without erasing concurrent fields.
use serde_json::Value;

pub fn rollback(previous: &Value, attempted: &Value, current: &Value) -> Value {
    if current == attempted {
        return previous.clone();
    }
    if let (Some(previous), Some(attempted), Some(current)) = (
        previous.as_object(),
        attempted.as_object(),
        current.as_object(),
    ) {
        let mut merged = current.clone();
        for key in previous.keys().chain(attempted.keys()) {
            let old = previous.get(key).unwrap_or(&Value::Null);
            let tried = attempted.get(key).unwrap_or(&Value::Null);
            let now = current.get(key).unwrap_or(&Value::Null);
            if old == tried {
                continue;
            }
            if !previous.contains_key(key) && now == tried {
                merged.remove(key);
            } else if current.contains_key(key) {
                merged.insert(key.clone(), rollback(old, tried, now));
            }
        }
        return Value::Object(merged);
    }
    // Arrays and scalar conflicts belong to the concurrent writer. Do not
    // guess identities or overwrite them with a stale whole-state snapshot.
    current.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rollback_keeps_nested_concurrent_fields_and_removes_owned_additions() {
        let previous = json!({"split":{"enabled":false,"cache":{"old":1}},"favorites":[1]});
        let attempted =
            json!({"split":{"enabled":true,"cache":{"old":1}},"favorites":[2],"new":42});
        let current = json!({"split":{"enabled":true,"cache":{"old":1,"concurrent":2}},"favorites":[2,3],"new":42});
        assert_eq!(
            rollback(&previous, &attempted, &current),
            json!({"split":{"enabled":false,"cache":{"old":1,"concurrent":2}},"favorites":[2,3]})
        );
    }
}
