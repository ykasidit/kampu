Kampu
-----

Generic byte array parser function where you can define the structure/tree of the bytes in JSON, send it a byte array and get the parsed output in JSON.

'Kampu' is the name a large tree common in Thailand, it has very large branches that could be allegorical to the complex bit/byte/loops/matches that this parser aims to handle.


History
-------

Inspired by the 'data' folder of [libqmi](https://github.com/linux-mobile-broadband/libqmi) and its python scripts to gen C code to match. Some GNSS device manufactureres sent new GNSS devices where they had their own packet structures to be added for the [bluetooth_gnss](https://github.com/ykasidit/bluetooth_gnss) app. Manually coding of these parsers and more complex protocols seem to call for a generic parser tool that could offer a simple way to define structures in JSON and have the safety, portability and performance of rust in which GPT helped draft most of the initial code in this repo and would hopefully be benefical to other common protocol dissector works too.
