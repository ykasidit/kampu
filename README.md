parsewala
---------

Generic byte array parser service where you can define the structure in JSON, send it an byte array and get the parsed output in JSON.

history
-------

Inspired by the 'data' folder of [libqmi](https://github.com/linux-mobile-broadband/libqmi) and its python scripts to gen C code to match. I was continuing my [bluetooth_gnss](https://github.com/ykasidit/bluetooth_gnss), so I was talking to GPT about a generic parser for new format of packets of GNSS manufacturers who sent me new GNSS devices where wanted to handle their packets formatted in some pdf and I didnt want to do manual coding to read/parse/skip bytes/bits anymore, so the GPT helped me draft most of the initial code in this repo and I thought it would be benefical to other protocol dissector/encoding works too.
