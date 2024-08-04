use std::any::{Any, TypeId};
use serde::Deserialize;
use serde_json::{Map, Value, Number};
use std::collections::{HashMap, HashSet};
use bitter::{BitReader, LittleEndianReader};
use evalexpr::{ContextWithMutableVariables, eval_float, eval_float_with_context, eval_float_with_context_mut, eval_int, eval_int_with_context, eval_string, eval_string_with_context, eval_with_context_mut, HashMapContext};

#[derive(Deserialize, Debug)]
struct Field {
    name: String,
    #[serde(rename = "type")]
    field_type: Option<String>,
    #[serde(rename = "match")]
    match_cases: Option<Map<String, Value>>,
    loop_count: Option<Value>,
    fields: Option<Vec<Field>>,
    optional: Option<bool>,
    eval: Option<String>
}

#[derive(Deserialize, Debug)]
struct Schema {
    fields: Vec<Field>,
}

fn read_bits(data: &[u8], bit_offset:usize, num_bits: u32) -> Result<(u64, usize), String> {
    let n_bytes_to_skip = bit_offset / 8;
    let n_bits_to_skip = (bit_offset % 8) as u32;
    let mut reader = if n_bytes_to_skip > 0 {
        LittleEndianReader::new(&data[n_bytes_to_skip..])
    } else {
        LittleEndianReader::new(data)
    };
    if n_bits_to_skip > 0 {
        _ = reader.read_bits(n_bits_to_skip);
    }
    let value = reader.read_bits(num_bits).ok_or(format!("Read failed: data len bits {} bit_offset {} attempt read num_bits: {}", data.len()*8, bit_offset, num_bits))?;
    let new_offset = bit_offset + num_bits as usize;
    Ok((value, new_offset))
}

fn evaluate_expression(value: Number, expression: &str) -> bool {
    if expression.starts_with("gt_") {
        if let Ok(threshold) = expression[3..].parse::<i64>() {
            return value.as_i64().unwrap() > threshold;
        }
    } else if expression.starts_with("ge_") {
        if let Ok(threshold) = expression[3..].parse::<i64>() {
            return value.as_i64().unwrap() >= threshold;
        }
    } else if expression.starts_with("lt_") {
        if let Ok(threshold) = expression[3..].parse::<i64>() {
            return value.as_i64().unwrap() < threshold;
        }
    } else if expression.starts_with("le_") {
        if let Ok(threshold) = expression[3..].parse::<i64>() {
            return value.as_i64().unwrap() <= threshold;
        }
    }
    false
}

fn verify_schema(schema: &[Field], known_fields: &mut HashSet<String>) -> bool {
    for field in schema {
        // Ensure the field has a name
        if field.name.is_empty() {
            println!("Error: A field is missing a name.");
            return false;
        }

        // Add the field name to the known fields set
        known_fields.insert(field.name.clone());

        // Check for valid entries
        if let Some(field_type) = &field.field_type {
            match field.loop_count.clone() {
                Some(loop_count) => {
                    match loop_count {
                        Value::Number(_) => {

                        }
                        Value::String(_) => {
                            let loop_field_name = &field_type[13..];
                            if !known_fields.contains(loop_field_name) {
                                println!("Error: Unknown field '{}' referenced in '{}'.", loop_field_name, field.name);
                                return false;
                            }
                        }
                        _ => {
                            panic!("unsupported loop_count value: {loop_count} - it must either be a number or a string name of a previous field");
                        }
                    }
                }
                None => {
                let valid_types = vec ! [
                "u8", "u8_le", "u8_be", "u16", "u16_le", "u16_be", "u32", "u32_le", "u32_be",
                "u64", "u64_le", "u64_be", "f32", "f32_le", "f32_be", "f64", "f64_le", "f64_be",
                "i16", "i16_le", "i16_be",
                ];
                if ! valid_types.contains( & field_type.as_str()) {
                println ! ("Error: Invalid type '{}' in field '{}'.", field_type, field.name);
                return false;
                }
                }
            }
        }

        let field_keys: Vec<String> = field
            .match_cases
            .as_ref()
            .map(|mc| mc.keys().cloned().collect())
            .unwrap_or_else(Vec::new);

        let all_keys = vec!["type", "fields"];

        for key in field_keys {
            if !all_keys.contains(&key.as_str()) && !key.starts_with("gt_") && !key.starts_with("ge_") && !key.starts_with("lt_") && !key.starts_with("le_") {
                println!("Error: Invalid key '{}' in match case of field '{}'.", key, field.name);
                return false;
            }
        }

        // Verify nested fields recursively
        if let Some(fields) = &field.fields {
            if !verify_schema(fields, known_fields) {
                return false;
            }
        }
    }
    true
}

pub fn get_field_size(field: &Field, val_cache: &mut HashMap<String, Value>) -> (u32, Option<u64>)
{
     if field.loop_count.is_some() {
        match field.loop_count.clone().unwrap() {
            Value::String(loop_field_name) => {
                if let Some(loop_count) = val_cache.get(&loop_field_name) {
                    println!("loop_count from loop_field_name {} val_cache {}", loop_field_name, loop_count);
                    (0, Some(loop_count.as_u64().unwrap()))
                } else {
                    panic!("Previous field {} not found for loop_count matching", loop_field_name);
                }
            }
            Value::Number(loop_count_static) => {
                (0, Some(loop_count_static.as_u64().unwrap()))
            }
            _ => {
                panic!("loop_count must be either a previous field name or a number");
            }
        }
    } else {
        let bits = match field.field_type.clone().unwrap().as_str() {
            "u8" | "u8_le" | "u8_be" => 8,
            "u16" | "u16_le" | "u16_be" => 16,
            "u32" | "u32_le" | "u32_be" => 32,
            "u64" | "u64_le" | "u64_be" => 64,
            "f32" | "f32_le" | "f32_be" => 32,
            "f64" | "f64_le" | "f64_be" => 64,
            "i16" | "i16_le" | "i16_be" => 16,
            t if t.starts_with('u') && t.len() > 1 => t[1..].parse().unwrap_or(0),
            _ => 0,
        };
        (bits, None)
    }
}

pub fn process_field(data: &[u8], field: &Field, dry_run: bool, value: Number, bit_offset:usize, prev_val_cache: &mut HashMap<String, Value>, parsed_data: &mut Map<String, Value>) -> Result<usize, (Value, String)>
{
    let mut new_bit_offset = bit_offset;
    if let Some(match_cases) = &field.match_cases {
        println!("match_cases: {:?}", match_cases);
        let mut matched = false;
        for (key, description) in match_cases {
            if key.starts_with("gt_") || key.starts_with("ge_") || key.starts_with("lt_") || key.starts_with("le_") {
                if evaluate_expression(value.clone(), key) {
                    parsed_data.insert(field.name.clone(), description.clone());
                    matched = true;
                    break;
                }
            } else if key == &value.to_string() {
                if let Some(obj) = description.as_object() {
                    println!("key matched: {} obj0", key);
                    if let Some(fields) = obj.get("fields").and_then(|f| f.as_array()) {
                        let nested_fields: Vec<Field> = serde_json::from_value(Value::Array(fields.clone())).unwrap();
                        let (mut nested_data, nested_bits) = parse_binary(&data[(bit_offset / 8)..], &nested_fields, dry_run, prev_val_cache)?;
                        new_bit_offset += nested_bits;
                        if nested_data.is_object() && obj.contains_key("name") {
                            let mut no = nested_data.as_object_mut().unwrap();
                            no.insert(
                                "name".to_string(),
                                obj.get("name").unwrap().clone()
                            );
                        }
                        parsed_data.insert(field.name.clone(), nested_data);
                    }

                } else {
                    println!("key matched: {} not object", key);
                    parsed_data.insert(field.name.clone(), description.clone());
                }
                matched = true;
                break;
            }
        }
        if !matched {
            parsed_data.insert(field.name.clone(), Value::String("unknown".to_string()));
        }
    } else {

        //make eval context
        let mut eval_context = HashMapContext::new();
        if value.is_f64() {
            eval_context.set_value("value_float".to_string(), value.as_f64().unwrap().into());
        } else if value.is_i64() {
            eval_context.set_value("value_int".to_string(), value.as_i64().unwrap().into());
        }
        eval_context.set_value("value_string".to_string(), value.to_string().into());

        match &field.eval {
            Some(evals) => {
                let eval_ret = eval_with_context_mut(evals.as_str(), &mut eval_context);
                match eval_ret {
                    Ok(ret) => {
                        println!("eval ret: {:?}", ret);
                        let mut ret_serde_value = if ret.is_float() {
                            Value::from(ret.as_float().unwrap())
                        } else if ret.is_int() {
                            Value::from(ret.as_int().unwrap())
                        } else if ret.is_boolean() {
                            Value::from(ret.as_boolean().unwrap())
                        } else {
                            Value::from(ret.to_string())
                        };
                        parsed_data.insert(field.name.clone(), ret_serde_value.clone());
                        prev_val_cache.insert(field.name.clone(), ret_serde_value.clone());
                    }
                    Err(emsg) => {
                        parsed_data.insert(field.name.clone()+"_eval_error", Value::from(format!("eval error: {}", emsg)));
                    }
                }
            }
            None => {
                parsed_data.insert(field.name.clone(), Value::from(value.clone()));
                prev_val_cache.insert(field.name.clone(), Value::from(value.clone()));
            }
        }
    }
    Ok(new_bit_offset)
}

pub fn parse_binary(
    data: &[u8],
    schema: &[Field],
    dry_run: bool,
    prev_val_cache: &mut HashMap<String, Value>,
) -> Result<(Value, usize), (Value, String)> {
    let mut bit_offset = 0;
    let mut parsed_data = Map::new();

    for field in schema {
        println!("proc field {:?}", field);
        if field.field_type.is_some() || field.loop_count.is_some() { //normal fields or loop
            let (field_bits, loop_count_option) = get_field_size(&field, prev_val_cache);
            if loop_count_option.is_none() && field_bits == 0 {
                println!("Invalid field - not a loop and no bits to parse: {:?}", field);
                continue;
            }
            if let Some(loop_count) = loop_count_option {  //loop around files
                println!("loop_count: {}", loop_count);
                let mut output_array:Vec<Value> = vec![];
                for _ in 0..loop_count {
                    let (nested_data, nested_bits) = parse_binary(&data[(bit_offset / 8)..], field.fields.as_ref().unwrap(), dry_run, prev_val_cache)?;
                    bit_offset += nested_bits;
                    output_array.push(nested_data);
                }
                parsed_data.insert(field.name.clone(), Value::Array(output_array));
            } else {
                let field_type = &field.field_type.clone().unwrap();
                let (value, new_bit_offset) = if !dry_run {read_bits(data, bit_offset, field_bits).map_err(|err| (Value::Object(parsed_data.clone()), err))?} else {(0, bit_offset as usize + field_bits as usize)};
                bit_offset = new_bit_offset;
                let final_value:Number = match field_type.as_str() {
                        "u8" | "u8_le" => Number::from(value as u8 as u32),
                        "u8_be" => Number::from(value as u8),
                        "u16" | "u16_le" => Number::from(u16::from_le_bytes((value as u16).to_le_bytes())),
                        "u16_be" => Number::from(u16::from_be_bytes((value as u16).to_be_bytes())),
                        "u32" | "u32_le" => Number::from(u32::from_le_bytes((value as u32).to_le_bytes())),
                        "u32_be" => Number::from(u32::from_be_bytes((value as u32).to_be_bytes())),
                        "u64" | "u64_le" => Number::from(u64::from_le_bytes((value as u64).to_le_bytes())),
                        "u64_be" => Number::from(u64::from_be_bytes((value as u64).to_be_bytes())),
                        "f32" | "f32_le" => Number::from_f64(f32::from_le_bytes((value as u32).to_le_bytes()) as f64).unwrap(),
                        "f32_be" => Number::from_f64(f32::from_be_bytes((value as u32).to_be_bytes()) as f64).unwrap(),
                        "f64" | "f64_le" => Number::from_f64(f64::from_le_bytes((value as u64).to_le_bytes()) as f64).unwrap(),
                        "f64_be" => Number::from_f64(f64::from_be_bytes((value as u64).to_be_bytes()) as f64).unwrap(),
                        "i16" | "i16_le" => Number::from(i16::from_le_bytes((value as u16).to_le_bytes())),
                        "i16_be" => Number::from(i16::from_be_bytes((value as u16).to_be_bytes())),
                        t if t.starts_with('u') => Number::from(value),
                        _ => {panic!("unsupported field_type: {}", field_type)},
                };
                println!("final_value: {:?}", final_value);
                bit_offset = process_field(data, field, dry_run, final_value, bit_offset, prev_val_cache, &mut parsed_data)?;
            }
        } else if let Some(fields) = &field.fields { //nested fields
            let (nested_data, nested_bits) = parse_binary(&data[(bit_offset / 8)..], fields, dry_run, prev_val_cache)?;
            bit_offset += nested_bits;
            parsed_data.insert(field.name.clone(), nested_data);
        } else {
            panic!("unsupported usage: {:?}", field);
        }
    }
    Ok((Value::Object(parsed_data), bit_offset))
}

pub fn hex_to_bin(hex: &str) -> Vec<u8>
{
    let hex_trimmed = hex.trim();
    let hex_no_space =  str::replace(hex_trimmed, " ", "").replace("\n","").replace("\r", "");
    println!("hex_no_space: {}", hex_no_space);
    hex::decode(hex_no_space).expect("Decoding failed")
}

#[cfg(test)]
mod tests {
    use evalexpr::{ContextWithMutableVariables, eval, eval_int, eval_int_with_context, HashMapContext};
    use once_cell::sync::Lazy;
    use super::*;
    use serde_json::json;

    fn parse_hex_string(hex_string: &str) -> Vec<u8> {
        hex_string
            .split_whitespace()
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect()
    }

    fn load_schema(schema_json: Value) -> Schema {
        serde_json::from_value(schema_json).expect("Unable to parse JSON schema")
    }

    #[test]
    fn test_simple_packet() {
        let schema_json = json!({
            "fields": [
                { "name": "fix_status", "type": "u8" },
                { "name": "rcr", "type": "u8" },
                { "name": "millisecond", "type": "u16_le" }
            ]
        });
        let data = parse_hex_string("01 00 E8 03");

        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, bit_offset) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();
        assert_eq!(bit_offset, 4*8);
        assert_eq!(parsed_json, json!({
            "fix_status": 1,
            "rcr": 0,
            "millisecond": 1000
        }));
    }

    #[test]
    fn test_nested_packet() {
        let schema_json = json!({
            "fields": [
                { "name": "header", "type": "u8" },
                { "name": "payload", "fields": [
                    { "name": "field1", "type": "u8" },
                    { "name": "field2", "type": "u16_le" }
                ]}
            ]
        });

        let data = parse_hex_string("01 02 E8 03");

        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();

        assert_eq!(parsed_json, json!({
            "header": 1,
            "payload": {
                "field1": 2,
                "field2": 1000
            }
        }));
    }

    #[test]
    fn test_match_num_to_string() {
        let schema_json = json!({
            "fields": [
                { "name": "status", "type": "u8", "match": {
                    "0": "Inactive",
                    "1": "Active"
                }}
            ]
        });

        let data = parse_hex_string("01");

        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();
        assert_eq!(parsed_json, json!({
            "status": "Active"
        }));
    }

    #[test]
    fn test_loop_fields() {
        let schema_json = json!({
            "fields": [
                { "name": "count", "type": "u8" },
                { "name": "reserved", "type": "u8" },
                { "name": "items", "loop_count":"count", "fields": [
                    { "name": "item", "type": "u8" }
                ]}
            ]
        });

        let data = parse_hex_string("03 FF 01 02 03");

        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();

        assert_eq!(parsed_json, json!({
            "count": 3,
            "reserved": 255,
            "items": [
                { "item": 1 },
                { "item": 2 },
                { "item": 3 }
            ]
        }));
    }

    #[test]
    fn test_match_to_nested_packet() {
        let schema_json = json!({
            "fields": [
                { "name": "type", "type": "u8", "match": {
                    "0": "Type0",
                    "1": {
                        "name": "Type1",
                        "fields": [
                            { "name": "field1", "type": "u8" },
                            { "name": "field2", "type": "u16_le" }
                        ]
                    }
                }}
            ]
        });
        let data = parse_hex_string("01 02 E8 03");

        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();

        assert_eq!(parsed_json, json!({
            "type": {
                "name": "Type1",
                "field1": 2,
                "field2": 1000
            }
        }));
    }

    #[test]
    fn test_dry_run() {
        let schema_json = json!({
            "fields": [
                { "name": "fix_status", "type": "u8" },
                { "name": "rcr", "type": "u8" },
                { "name": "millisecond", "type": "u16_le" }
            ]
        });

        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, _) = parse_binary(&[], &schema.fields, true, &mut previous_values).unwrap();
        assert_eq!(parsed_json, json!({
            "fix_status": 0,
            "millisecond": 0,
            "rcr": 0
        }));
    }

    #[test]
    fn test_coral_reef() {
        let coral_reef_structure_json = json!({
            "fields": [
                { "name": "nature_reserve_id", "type": "u16" },
                { "name": "n_colonies", "type": "u32" },
                { "name": "region_id", "type": "u16" },
                {
                "name": "colonies", "loop_count": "n_colonies", "fields": [
                    { "name": "n_polyps", "type": "u32" },
                    { "name": "polyps", "loop_count": "n_polyps", "fields": [
                        { "name": "polyp_id", "type": "u32" },
                        { "name": "polyp_type", "type": "u8" }
                    ]
                    }
                ]
                }
            ]
        });

        let data = parse_hex_string(r#"
        fe ff
        01 00 00 00
        04 00
        02 00 00 00
        00 00 00 00
        01
        01 00 00 00
        01
        "#);

        let schema = load_schema(coral_reef_structure_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();

        assert_eq!(parsed_json, json!({
            "n_colonies": 1,
            "nature_reserve_id": 65534,
            "region_id": 4,
            "colonies": [
                {
                    "n_polyps": 2,
                    "polyps": [
                    { "polyp_id": 0, "polyp_type": 1},
                    { "polyp_id": 1, "polyp_type": 1}
                ]
                }
            ]
        }));
    }

    ////////////////// qstarz_ble tests
    /*
    ref formula:
    int tmp_lat = dLat / 100;
    int tmp_lon = dLon / 100;
    dLat = tmp_lat + (dLat - tmp_lat * 100) / 60.0;
    dLon = tmp_lon + (dLon - tmp_lon * 100) / 60.0;
    */
    const qstarz_lat_lon_DDDMM_MMMM_formula:&str = r#"
    tmp_lat = value_float / 100;
    tmp_lat + (value_float - tmp_lat * 100) / 60.0
    "#;
    const qstarz_ble_schema: Lazy<Schema> = Lazy::new(|| {
        load_schema(
            json!({
                "fields": [
                    { "name": "fix_status", "type": "u8",
                        "match": {
                        "1": "Fix not available",
                        "2": "2D",
                        "3": "3D",
                    }
                    },
                    { "name": "rcr", "type": "u8" },
                    { "name": "millisecond", "type": "u16" },
                    { "name": "latitude", "type": "f64", "eval": qstarz_lat_lon_DDDMM_MMMM_formula },
                    { "name": "longitude", "type": "f64", "eval": qstarz_lat_lon_DDDMM_MMMM_formula },
                    { "name": "timestamp_s", "type": "u32" },
                    { "name": "float_speed_kmh", "type": "f32" },
                    { "name": "float_height_m", "type": "f32" },
                    { "name": "heading_degrees", "type": "f32" },
                    { "name": "g_sensor_x", "type": "i16" },
                    { "name": "g_sensor_y", "type": "i16" },
                    { "name": "g_sensor_z", "type": "i16" },
                    { "name": "max_snr", "type": "u16" },
                    { "name": "hdop", "type": "f32" },
                    { "name": "vdop", "type": "f32" },
                    { "name": "satellite_count_view", "type": "u8" },
                    { "name": "satellite_count_used", "type": "u8" },
                    { "name": "fix_quality", "type": "u8",
                        "match": {
                        "0": "invalid",
                        "1":  "GPS fix (SPS)",
                        "2": "DGPS fix",
                        "3": "PPS fix",
                        "4": "Real Time Kinematic",
                        "5": "Float RTK",
                        "6": "estimated (dead reckoning) (2.3 feature)",
                        "7": "Manual input mode",
                        "8": "Simulation mode"
                    }
                    },
                    { "name": "battery_percent", "type": "u8" },
                    { "name": "dummy", "type": "u16" },
                    { "name": "series_number", "type": "u8" },
                    {
                        "name": "gsv_fields",
                        "loop_count": 3,
                        "fields": [
                        { "name": "prn", "type": "u8" },
                        { "name": "elevation", "type": "u16" },
                        { "name": "azimuth", "type": "u16" },
                        { "name": "snr", "type": "u8" }
                        ]
                    }
            ]
            })
        )
    });




    #[test]
    fn test_qstarz_ble_packet_gps_not_fixed()
    {
        /*
        19:03:33.506 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <01547801 00000000 00000080 00000000 00000080> 	01=GPS is not fixed
        19:03:33.506 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <85f2de60 61a6fd3f 00000000 14aeca42 6800a9ff>
        19:03:33.507 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <46001400 00000000 00000000 0d00003c 00000000>
        19:03:33.507 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <05460300 3b000041 0c001300 00551100 b00000> 	05=GSV #5
        */
        let data = hex_to_bin(r#"
        01547801 00000000 00000080 00000000 00000080
        85f2de60 61a6fd3f 00000000 14aeca42 6800a9ff
        46001400 00000000 00000000 0d00003c 00000000
        05460300 3b000041 0c001300 00551100 b00000
        "#
        );
        let mut val_cache = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &qstarz_ble_schema.fields, false, &mut val_cache).unwrap();
        println!("parsed_json: {}", serde_json::to_string_pretty(&parsed_json).unwrap());
        assert_eq!(
            parsed_json,
            json!( {
                "fix_status": "Fix not available",
                "rcr": 84,
                "millisecond": 376,
                "latitude": -0.0,
                "longitude": -0.0,
                "timestamp_s": 1625223813,
                "float_speed_kmh": 1.9816399812698364,
                "float_height_m": 0.0,
                "heading_degrees": 101.33999633789062,
                "g_sensor_x": 104,
                "g_sensor_y": -87,
                "g_sensor_z": 70,
                "max_snr": 20,
                "hdop": 0.0,
                "vdop": 0.0,
                "satellite_count_view": 13,
                "satellite_count_used": 0,
                "fix_quality": "invalid",
                "battery_percent": 60,
                "dummy": 0,
                "series_number": 0,
                "gsv_fields": [
                    {
                        "prn": 0,
                        "elevation": 17925,
                        "azimuth": 3,
                        "snr": 59
                    },
                    {
                        "prn": 0,
                        "elevation": 16640,
                        "azimuth": 12,
                        "snr": 19
                    },
                    {
                        "prn": 0,
                        "elevation": 21760,
                        "azimuth": 17,
                        "snr": 176
                    }
                ]
            }
            )
        );
    }

    #[test]
    fn test_qstarz_ble_packet_gps_fixed_wo_gsv()
    {
        /*
        19:03:34.403 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <0354c800 cd94d6df 8a91a340 821e6adb 2eadc740>  	03=GPS is fixed
        19:03:34.403 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <86f2de60 3a924340 10c89943 ec51c842 610077ff>
        19:03:34.404 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <72001300 b81ee53f ec51783f 0d05013c 0000>
        */
        let data = hex_to_bin(r#"
        0354c800 cd94d6df 8a91a340 821e6adb 2eadc740
        86f2de60 3a924340 10c89943 ec51c842 610077ff
        72001300 b81ee53f ec51783f 0d05013c 0000
        "#
        );
        let mut val_cache = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &qstarz_ble_schema.fields, false, &mut val_cache).err().unwrap();
        println!("parsed_json: {}", serde_json::to_string_pretty(&parsed_json).unwrap());
        assert_eq!(
            parsed_json,
            json!({
                "battery_percent": 60,
                "dummy": 0,
                "fix_quality": "GPS fix (SPS)",
                "fix_status": "3D",
                "float_height_m": 307.56298828125,
                "float_speed_kmh": 3.055799961090088,
                "g_sensor_x": 97,
                "g_sensor_y": -137,
                "g_sensor_z": 114,
                "hdop": 1.7899999618530273,
                "heading_degrees": 100.16000366210938,
                "latitude": 25.04771239,
                "longitude": 121.22366071,
                "max_snr": 19,
                "millisecond": 200,
                "rcr": 84,
                "satellite_count_used": 5,
                "satellite_count_view": 13,
                "timestamp_s": 1625223814,
                "vdop": 0.9700000286102295
            })
        );

        //////////////////////////

    }

    #[test]
    fn test_eval_expr()
    {
        let mut eval_context = HashMapContext::new();
        eval_context.set_value("a".to_string(), 1.into());
        assert_eq!(eval_int_with_context("a + 1 + 2 + 3", &eval_context), Ok(7));

        //cases for  eval int/float/str
        let schema_json = json!({
            "fields": [
                { "name": "sth", "type": "u8", "eval": "value_int + 1"},
            ]
        });
        let data = parse_hex_string("01");
        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, bit_offset) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();
        assert_eq!(bit_offset, 8);
        assert_eq!(parsed_json, json!({
            "sth": 2,
        }));

        let schema_json = json!({
            "fields": [
                { "name": "sth", "type": "u8", "eval": "value_int + 1.0"},
            ]
        });
        let data = parse_hex_string("01");
        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, bit_offset) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();
        assert_eq!(bit_offset, 8);
        assert_eq!(parsed_json, json!({
            "sth": 2.0,
        }));

        let schema_json = json!({
            "fields": [
                { "name": "sth", "type": "u8", "eval": "math::pow(value_int, 2)"},
            ]
        });
        let data = parse_hex_string("0A");
        let schema = load_schema(schema_json);
        let mut previous_values = HashMap::new();
        let (parsed_json, bit_offset) = parse_binary(&data, &schema.fields, false, &mut previous_values).unwrap();
        assert_eq!(bit_offset, 8);
        assert_eq!(parsed_json, json!({
            "sth": 100.0,
        }));
    }

    #[test]
    fn test_qstarz_ble_packet_gps_fixed_w_gsv()
    {
        /*
        19:03:34.555 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <03549001 faf202ec 8b91a340 69519fe4 2eadc740>  	03=GPS is fixed
        19:03:34.555 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <86f2de60 40de4b40 aec79943 5c8fd442 480082ff>
        19:03:34.555 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <52001100 b81ee53f ec51783f 0d05013c 00000000>
        19:03:34.555 - Characteristic (6E400004-B5A3-F393-E0A9-E50E24DCCA9E) notified: <05460300 3b000041 0c001300 00551100 b00000> 	05=GSV #5
        */
        let data = hex_to_bin(r#"
        03549001 faf202ec 8b91a340 69519fe4 2eadc740
        86f2de60 40de4b40 aec79943 5c8fd442 480082ff
        52001100 b81ee53f ec51783f 0d05013c 00000000
        05460300 3b000041 0c001300 00551100 b00000
        "#
        );
        let mut val_cache = HashMap::new();
        let (parsed_json, _) = parse_binary(&data, &qstarz_ble_schema.fields, false, &mut val_cache).unwrap();
        println!("parsed_json: {}", serde_json::to_string_pretty(&parsed_json).unwrap());
        assert_eq!(
            parsed_json,
            json!({
                "fix_status": "3D",
                "rcr": 84,
                "millisecond": 400,
                "latitude": 25.047732850000003,
                "longitude": 121.22366351999999,
                "timestamp_s": 1625223814,
                "float_speed_kmh": 3.1854400634765625,
                "float_height_m": 307.55999755859375,
                "heading_degrees": 106.27999877929688,
                "g_sensor_x": 72,
                "g_sensor_y": -126,
                "g_sensor_z": 82,
                "max_snr": 17,
                "hdop": 1.7899999618530273,
                "vdop": 0.9700000286102295,
                "satellite_count_view": 13,
                "satellite_count_used": 5,
                "fix_quality": "GPS fix (SPS)",
                "battery_percent": 60,
                "dummy": 0,
                "series_number": 0,
                "gsv_fields": [
                    {
                        "prn": 0,
                        "elevation": 17925,
                        "azimuth": 3,
                        "snr": 59
                    },
                    {
                        "prn": 0,
                        "elevation": 16640,
                        "azimuth": 12,
                        "snr": 19
                    },
                    {
                        "prn": 0,
                        "elevation": 21760,
                        "azimuth": 17,
                        "snr": 176
                    }
                ]
            }
            )
        );
        //////////////////////////

    }
}
