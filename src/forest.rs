use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use serde_json::Value;
use crate::tree::{parse_schema, Tree, schema_to_tree};
use serde_json::json;
use crate::utils::hex_to_bin;

static PLANTED_TREES:Lazy<Mutex<HashMap<u64, Tree>>> = Lazy::new(|| {
    let hm:HashMap<u64, Tree> = HashMap::new();
    Mutex::new(hm)
});

pub fn plant_tree_schema(unique_tree_id:u64, schema: Tree) -> i32 {
    let mut hm = PLANTED_TREES.lock().unwrap();
    hm.insert(unique_tree_id, schema);
    0
}

pub fn plant_tree(unique_tree_id:u64, schema: Value) -> i32 {
    plant_tree_schema(unique_tree_id, schema_to_tree(schema))
}

pub fn parse_tree(
    unique_tree_id: u64,
    data: &[u8]
) -> Value
{
    let schema = {
        //use this block to quickly get, clone and release the lock on the mutex-locked map
        let reg_map = PLANTED_TREES.lock().unwrap();
        let sr = reg_map.get(&unique_tree_id).unwrap();
        let so = sr.clone();
        so
    };
    let mut previous_values = HashMap::new();
    let (parsed_json, _) = parse_schema(&data, &schema.branches, false, &mut previous_values).unwrap();
    parsed_json
}

#[test]
fn test_simple_packet() {
    const tree_id:u64 = 1;
    let data = hex_to_bin("01 00 E8 03");
    plant_tree(
        tree_id,
        json!({
                "branches": [
                    { "name": "fix_status", "type": "u8" },
                    { "name": "rcr", "type": "u8" },
                    { "name": "millisecond", "type": "u16_le" }
                ]
            })
    );
    let parsed_json = parse_tree(tree_id, &data);
    assert_eq!(parsed_json, json!({
            "fix_status": 1,
            "rcr": 0,
            "millisecond": 1000
        }));
}