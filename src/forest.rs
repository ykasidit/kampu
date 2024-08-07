use std::collections::HashMap;
use std::sync::{Mutex};
use once_cell::sync::Lazy;
use serde_json::Value;

use crate::tree::{parse_schema, schema_to_tree, Tree};

pub static PLANTED_PARSE_TREES:Lazy<Mutex<HashMap<u64, Tree>>> = Lazy::new(|| {
    let hm:HashMap<u64, Tree> = HashMap::new();
    Mutex::new(hm)
});

pub fn is_tree_planted(unique_tree_id:u64) -> bool {
    PLANTED_PARSE_TREES.lock().unwrap().contains_key(&unique_tree_id)
}

pub fn plant_tree_schema(unique_tree_id:u64, schema: Tree) -> i32 {
    let mut hm = PLANTED_PARSE_TREES.lock().unwrap();
    hm.insert(unique_tree_id, schema);
    0
}

pub fn plant_tree(unique_tree_id:u64, schema: Value) -> i32 {
    plant_tree_schema(unique_tree_id, schema_to_tree(schema))
}

pub fn parse_tree(
    unique_tree_id: u64,
    data: &[u8]
) -> Result<Value, String>
{
    let schema:Tree = {
        //use this block to quickly get, clone and release the lock on the mutex-locked map
        let reg_map = PLANTED_PARSE_TREES.lock().unwrap();
        let sr = reg_map.get(&unique_tree_id).ok_or(format!("No tree with unique_tree_id {} found", unique_tree_id))?;
        let so = sr.clone();
        so
    };

    let mut previous_values = HashMap::new();
    let parse_ret = parse_schema(&data, &schema.branches, false, &mut previous_values);
    match parse_ret {
        Ok((parsed_json, _parse_pos)) => {
            Ok(parsed_json)
        }
        Err((partially_parsed_json, errstr)) => {
            println!("WARNING: parse_schema() failed with error: {errstr}, returning partially_parsed_json struct");
            Ok(partially_parsed_json)
        }
    }
}

#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use crate::utils::hex_to_bin;

#[test]
fn test_simple_packet() {
    const TREE_ID:u64 = 1;
    let data = hex_to_bin("01 00 E8 03");
    plant_tree(
        TREE_ID,
        json!({
                "branches": [
                    { "name": "fix_status", "type": "u8" },
                    { "name": "rcr", "type": "u8" },
                    { "name": "millisecond", "type": "u16_le" }
                ]
            })
    );
    let parsed_json = parse_tree(TREE_ID, &data).unwrap();
    assert_eq!(parsed_json, json!({
            "fix_status": 1,
            "rcr": 0,
            "millisecond": 1000
        }));
}