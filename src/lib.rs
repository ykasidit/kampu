use serde::Deserialize;
use serde_json::{Map, Value, Number};
use std::collections::{HashMap, HashSet};
use bitter::{BitReader, LittleEndianReader};

#[derive(Deserialize, Debug)]
struct Field {
    name: String,
    #[serde(rename = "type")]
    field_type: Option<String>,
    #[serde(rename = "match")]
    match_cases: Option<Map<String, Value>>,
    loop_count: Option<Value>,
    fields: Option<Vec<Field>>,
    optional: Option<bool>
}

#[derive(Deserialize, Debug)]
struct Schema {
    fields: Vec<Field>,
}

fn parse_bits(data: &[u8], bit_offset:usize, num_bits: u32) -> (u64, usize) {
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
    let value = reader.read_bits(num_bits).unwrap();
    let new_offset = bit_offset + num_bits as usize;
    (value, new_offset)
}

fn evaluate_expression(value: u64, expression: &str) -> bool {
    if expression.starts_with("gt_") {
        if let Ok(threshold) = expression[3..].parse::<u64>() {
            return value > threshold;
        }
    } else if expression.starts_with("ge_") {
        if let Ok(threshold) = expression[3..].parse::<u64>() {
            return value >= threshold;
        }
    } else if expression.starts_with("lt_") {
        if let Ok(threshold) = expression[3..].parse::<u64>() {
            return value < threshold;
        }
    } else if expression.starts_with("le_") {
        if let Ok(threshold) = expression[3..].parse::<u64>() {
            return value <= threshold;
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

pub fn get_field_size(field: &Field, previous_values: &mut HashMap<String, u64>) -> (u32, Option<u64>)
{
     if field.loop_count.is_some() {
        match field.loop_count.clone().unwrap() {
            Value::String(loop_field_name) => {
                if let Some(&loop_count) = previous_values.get(&loop_field_name) {
                    println!("loop_count from previous_values {}", loop_count);
                    (0, Some(loop_count))
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

pub fn parse_binary(
    data: &[u8],
    schema: &[Field],
    dry_run: bool,
    previous_values: &mut HashMap<String, u64>,
) -> (Value, usize) {
    if dry_run {
        let mut known_fields = HashSet::new();
        if !verify_schema(schema, &mut known_fields) {
            panic!("Schema verification failed.");
        }
        println!("Schema verification succeeded.");
        return (Value::Null, 0);
    }

    let mut bit_offset = 0;
    let mut parsed_data = Map::new();

    for field in schema {
        println!("proc field {:?}", field);
        if field.field_type.is_some() || field.loop_count.is_some() {
            let (field_bits, loop_count_option) = get_field_size(&field, previous_values);
            if loop_count_option.is_none() && field_bits == 0 {
                println!("Invalid field - not a loop and no bits to parse: {:?}", field);
                continue;
            }

            let mut process_field = |value: u64, bit_offset:usize| -> usize {
                let mut new_bit_offset = bit_offset;
                if let Some(match_cases) = &field.match_cases {
                    println!("match_cases: {:?}", match_cases);
                    let mut matched = false;
                    for (key, description) in match_cases {
                        if key.starts_with("gt_") || key.starts_with("ge_") || key.starts_with("lt_") || key.starts_with("le_") {
                            if evaluate_expression(value, key) {
                                parsed_data.insert(field.name.clone(), description.clone());
                                matched = true;
                                break;
                            }
                        } else if key == &value.to_string() {
                            if let Some(obj) = description.as_object() {
                                println!("key matched: {} obj0", key);
                                if let Some(fields) = obj.get("fields").and_then(|f| f.as_array()) {
                                    let nested_fields: Vec<Field> = serde_json::from_value(Value::Array(fields.clone())).unwrap();
                                    let (mut nested_data, nested_bits) = parse_binary(&data[(bit_offset / 8)..], &nested_fields, dry_run, previous_values);
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
                    parsed_data.insert(field.name.clone(), Value::Number(value.into()));
                }
                previous_values.insert(field.name.clone(), value);
                new_bit_offset
            };

            if let Some(loop_count) = loop_count_option {
                println!("loop_count: {}", loop_count);
                let mut output_array:Vec<Value> = vec![];
                for _ in 0..loop_count {
                    let (nested_data, nested_bits) = parse_binary(&data[(bit_offset / 8)..], field.fields.as_ref().unwrap(), dry_run, previous_values);
                    bit_offset += nested_bits;
                    output_array.push(nested_data);
                }
                parsed_data.insert(field.name.clone(), Value::Array(output_array));
            } else {
                let field_type = &field.field_type.clone().unwrap();
                if !dry_run {
                    let (value, new_bit_offset) = parse_bits(data, bit_offset, field_bits);
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
                            _ => Number::from_f64(0.0/0.0).unwrap(),
                    };
                    bit_offset = process_field(final_value.as_u64().unwrap(), bit_offset);
                } else {
                    bit_offset = process_field(0, bit_offset); // For dry_run, just add a placeholder value
                }
            }
        } else if let Some(fields) = &field.fields {
            let (nested_data, nested_bits) = parse_binary(&data[(bit_offset / 8)..], fields, dry_run, previous_values);
            bit_offset += nested_bits;
            parsed_data.insert(field.name.clone(), nested_data);
        }
    }
    (Value::Object(parsed_data), bit_offset)
}

#[cfg(test)]
mod tests {
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
        let (parsed_json, bit_offset) = parse_binary(&data, &schema.fields, false, &mut previous_values);
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
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values);

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
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values);

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
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values);

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
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values);

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
        let (parsed_json, _) = parse_binary(&[], &schema.fields, true, &mut previous_values);

        assert_eq!(parsed_json, Value::Null);
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
        let (parsed_json, _) = parse_binary(&data, &schema.fields, false, &mut previous_values);

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

      #[test]
    fn test_qstarz_ble_packet()
    {
        let schema = load_schema(json!({
            "fields": [
            { "name": "fix_status", "type": "u8" },
            { "name": "rcr", "type": "u8" },
            { "name": "millisecond", "type": "u16" },
            { "name": "latitude", "type": "f64" },
            { "name": "longitude", "type": "f64" },
            { "name": "timestamp", "type": "u32" },
            { "name": "speed", "type": "f32" },
            { "name": "height", "type": "f32" },
            { "name": "heading", "type": "f32" },
            { "name": "g_sensor_x", "type": "i16" },
            { "name": "g_sensor_y", "type": "i16" },
            { "name": "g_sensor_z", "type": "i16" },
            { "name": "max_snr", "type": "u16" },
            { "name": "hdop", "type": "f32" },
            { "name": "vdop", "type": "f32" },
            { "name": "satellite_count_view", "type": "u8" },
            { "name": "satellite_count_used", "type": "u8" },
            { "name": "fix_quality", "type": "u8" },
            { "name": "battery_percent", "type": "u8" },
            { "name": "dummy", "type": "u16" },
            {
                "name": "gsv_data",
                "type": "struct",
                "optional": true,
                "fields": [
                { "name": "series_number", "type": "u8" },
                {
                    "name": "gsv_fields",
                    "type": "struct",
                    "loop_count": 3,
                    "fields": [
                    { "name": "prn", "type": "u8" },
                    { "name": "elevation", "type": "u16" },
                    { "name": "azimuth", "type": "u16" },
                    { "name": "snr", "type": "u8" }
                    ]
                }
            ]
            }
            ]
        }));

    }
}
