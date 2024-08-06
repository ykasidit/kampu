Kampu
-----

Generic byte array parser function where you can define the structure/tree of the bytes in JSON, send it a byte array and get the parsed output in JSON.

'Kampu' is the name a large tree common in Thailand, it has very large branches that could be allegorical to the complex bit/byte/loops/matches that this parser aims to handle.

Usage
-----

See tests towards the bottom of the `tree.rs` file, example:
<pre>
 #[test]
    fn test_simple_packet() {
        let schema_json = json!({
            "branches": [
                { "name": "fix_status", "type": "u8" },
                { "name": "rcr", "type": "u8" },
                { "name": "millisecond", "type": "u16_le" }
            ]
        });
        let data = parse_hex_string("01 00 E8 03");
        let schema = load_schema(schema_json);
        forest_add_tree(1, schema);
        let parsed_json = forest_parse_tree(1, &data);
        assert_eq!(parsed_json, json!({
            "fix_status": 1,
            "rcr": 0,
            "millisecond": 1000
        }));
    }
</pre>


History
-------

Inspired by the 'data' folder of [libqmi](https://github.com/linux-mobile-broadband/libqmi) and its python scripts to gen C code to match. Some GNSS device manufactureres sent new GNSS devices where they had their own packet structures to be added for the [bluetooth_gnss](https://github.com/ykasidit/bluetooth_gnss) app. Manually coding of these parsers and more complex protocols seem to call for a generic parser tool that could offer a simple way to define structures in JSON and have the safety, portability and performance of rust in which GPT helped draft most of the initial code in this repo and would hopefully be benefical to other common protocol dissector works too.
