use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use serde_json::Value;
use crate::tree::{parse_tree, Tree};

static REG_SCHEMA_MAP:Lazy<Mutex<HashMap<u64, Tree>>> = Lazy::new(|| {
    let hm:HashMap<u64, Tree> = HashMap::new();
    Mutex::new(hm)
});

pub fn forest_add_tree(unique_tree_id:u64, schema: Tree) -> i32 {
    let mut hm = REG_SCHEMA_MAP.lock().unwrap();
    hm.insert(unique_tree_id, schema);
    0
}

pub fn forest_parse_tree(
    unique_tree_id: u64,
    data: &[u8]
) -> Value
{
    let schema = {
        //use this block to quickly get, clone and release the lock on the mutex-locked map
        let reg_map = REG_SCHEMA_MAP.lock().unwrap();
        let sr = reg_map.get(&unique_tree_id).unwrap();
        let so = sr.clone();
        so
    };
    let mut previous_values = HashMap::new();
    let (parsed_json, _) = parse_tree(&data, &schema.branches, false, &mut previous_values).unwrap();
    parsed_json
}