from flask import Flask, jsonify, request
import requests
import json
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser

app = Flask(__name__)

response = requests.get("https://raw.githubusercontent.com/Aryan-create-bot/token/main/version.txt").text
RELEASEVERSION = response.strip().split('=')[1].strip().replace('"', '')

# AES keys
key = b'Yg&tc%DEuh6%Zc^8'
iv = b'6oyZDr22E3ychjM%'


# --- AES Encrypt ---
def encrypt_api(plain_text_hex):
    plain_bytes = bytes.fromhex(plain_text_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_bytes, AES.block_size))
    return cipher_text.hex()


# --- Protobuf Encoding Helpers ---
def encode_varint(value):
    result = bytearray()
    while True:
        to_write = value & 0x7F
        value >>= 7
        if value:
            result.append(to_write | 0x80)
        else:
            result.append(to_write)
            break
    return bytes(result)


def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0
    return encode_varint(field_header) + encode_varint(value)


def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return encode_varint(field_header) + encode_varint(len(encoded_value)) + encoded_value


def create_protobuf_packet(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, list):
            for item in value:
                nested_packet = create_protobuf_packet(item)
                packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length_delimited_field(field, value))
    return packet


# --- Decode Parser ---
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == "string":
            field_data['data'] = result.data
            result_dict[result.field] = field_data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
            result_dict[result.field] = field_data
    return result_dict

def get_available_room(input_text):
    parsed_results = Parser().parse(input_text)
    parsed_results_dict = parse_results(parsed_results)
    return json.dumps(parsed_results_dict)


# --- API Request ---
def get_info(token, uid):
    USERAGENT = random.choice(["Dalvik/2.1.0 (Linux; U; Android 10; SM-J600F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 12; SM-A135F Build/SP1A.210812.016)","Dalvik/2.1.0 (Linux; U; Android 11; SM-A205F Build/RP1A.200720.012)","Dalvik/2.1.0 (Linux; U; Android 9; SM-M115F Build/QP1A.190711.019)","Dalvik/2.1.0 (Linux; U; Android 13; SM-A307FN Build/UP1A.230505.007)","Dalvik/2.1.0 (Linux; U; Android 10; SM-G610F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 11; SM-A025F Build/RP1A.200720.012)","Dalvik/2.1.0 (Linux; U; Android 12; SM-A515F Build/SP1A.210812.016)","Dalvik/2.1.0 (Linux; U; Android 13; SM-A145P Build/UP1A.230505.007)","Dalvik/2.1.0 (Linux; U; Android 10; SM-A217F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 11; SM-A225F Build/RP1A.200720.012)","Dalvik/2.1.0 (Linux; U; Android 9; SM-J730F Build/QP1A.190711.019)","Dalvik/2.1.0 (Linux; U; Android 12; SM-M105F Build/SP1A.210812.016)","Dalvik/2.1.0 (Linux; U; Android 10; SM-G532F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 13; SM-A105F Build/UP1A.230505.007)","Dalvik/2.1.0 (Linux; U; Android 10; SM-A205F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 11; SM-J600F Build/RP1A.200720.012)","Dalvik/2.1.0 (Linux; U; Android 12; SM-A515F Build/SP1A.210812.016)","Dalvik/2.1.0 (Linux; U; Android 13; SM-A135F Build/UP1A.230505.007)","Dalvik/2.1.0 (Linux; U; Android 9; SM-J730F Build/QP1A.190711.019)","Dalvik/2.1.0 (Linux; U; Android 10; SM-A217F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 11; SM-A025F Build/RP1A.200720.012)","Dalvik/2.1.0 (Linux; U; Android 12; SM-A105F Build/SP1A.210812.016)","Dalvik/2.1.0 (Linux; U; Android 13; SM-M115F Build/UP1A.230505.007)","Dalvik/2.1.0 (Linux; U; Android 10; SM-G610F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 11; SM-A145P Build/RP1A.200720.012)","Dalvik/2.1.0 (Linux; U; Android 12; SM-A307FN Build/SP1A.210812.016)","Dalvik/2.1.0 (Linux; U; Android 13; SM-A225F Build/UP1A.230505.007)","Dalvik/2.1.0 (Linux; U; Android 10; SM-J600F Build/QP1A.190711.020)","Dalvik/2.1.0 (Linux; U; Android 11; SM-A515F Build/RP1A.200720.012)"])
    url = "https://clientbp.ggblueshark.com/GetAccountInfoByAccountID"
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "Authorization": f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION
    }
    fields = {1: uid, 2: 4}
    data = create_protobuf_packet(fields)
    encrypted_data = encrypt_api(data.hex())
    encrypted_bytes = bytes.fromhex(encrypted_data)
    response = requests.post(url, headers=headers, data=encrypted_bytes)
    return response

# --- Flask Endpoint ---
@app.route('/api/region', methods=['GET'])
def api_get_info():
    try:
        uid = request.args.get("uid", type=int)
        if not uid:
            return jsonify({"error": "Please provide uid as query parameter"}), 400

        # Fetch token from GitHub JSON
        token_json = requests.get("https://raw.githubusercontent.com/Aryan-create-bot/token/main/token_bd.json").json()
        token = token_json["info_account"]["token"]

        # Get encrypted protobuf response
        response = get_info(token, uid)
        result = get_available_room(response.content.hex())
        parsed_data = json.loads(result)

        return jsonify({
            "player_info": {
                "name": parsed_data["3"]["data"],
                "region": parsed_data["5"]["data"],
                "level": parsed_data["6"]["data"]
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)