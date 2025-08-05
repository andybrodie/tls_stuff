import base64

# HPKE_KEM_IDS: A dictionary mapping HPKE KEM (Key Encapsulation Mechanism) IDs to their names.
HPKE_KEM_IDS = {
    0x0010: "P-256",  # NIST P-256 elliptic curve
    0x0011: "P-384",  # NIST P-384 elliptic curve
    0x0012: "P-521",  # NIST P-521 elliptic curve
    0x0020: "X25519", # Curve25519 elliptic curve
    0x0021: "X448"    # Curve448 elliptic curve
}

# HPKE_KDF_IDS: A dictionary mapping HPKE KDF (Key Derivation Function) IDs to their names.
HPKE_KDF_IDS = {
    0x0001: "HKDF-SHA256",
    0x0002: "HKDF-SHA384",
    0x0003: "HKDF-SHA512"
}

# HPKE_AEAD_IDS: A dictionary mapping HPKE AEAD (Authenticated Encryption with Associated Data) IDs to their names.
HPKE_AEAD_IDS = {
    0x0001: "AES-128-GCM",
    0x0002: "AES-256-GCM",
    0x0003: "ChaCha20-Poly1305",
    0xFFFF: "Export-only"
}

def get_line_start(data, offset, length):
    """
    Returns a formatted string used to start each line of the output,
    including the offset and the range of bytes being displayed.

    Args:
        data (bytes): The byte array being parsed.
        offset (int): The starting offset of the data to be displayed.
        length (int): The length of the data to be displayed.

    Returns:
        str: String in the format "[offset_start-offset_end] [hexadecimal representation]"

    """
    string_fragments = []
    string_fragments.append(f"[{offset:02x}-{(offset+length-1):02x}] [")
    hex_digits = []
    for i in range(length):
        hex_digits.append(f"{data[offset+i]:02x}")
    string_fragments.append(" ".join(hex_digits))
    string_fragments.append("]")
    return "".join(string_fragments)

def print_num(data, offset, description, size, base=10):
    """
    Outputs a numeric value from the byte array at the specified offset.

    Args:
        data (bytes): The byte array containing the data.
        offset (int): The offset in the byte array where the numeric value starts.
        description (str): A description of the numeric value being displayed.
        size (int): The size of the numeric value in bytes (1 for byte, 2 for int).
        base (int): The base for displaying the number (10 for decimal, 16 for hexadecimal).
    """
    value =0
    if size == 1:
        value = data[offset]
    else:
        value = int.from_bytes(data[offset:offset+size], 'big')

    string_fragments = [ f"{get_line_start(data, offset, size)} {description}:" ]
    if base == 16: 
        if size == 1:
            string_fragments.append(f"0x{value:02x}")
        else: 
            string_fragments.append(f"0x{value:04x}")
    else:
        string_fragments.append(f"{value}")
    print(" ".join(string_fragments))
    return size, value

def print_int(data, offset, description, base=10):
    """
    Outputs a 2-byte integer value from the byte array at the specified offset.

    Args:
        data (bytes): The byte array containing the data.
        offset (int): The offset in the byte array where the integer value starts.
        description (str): A description of the integer value being displayed.
        base (int): The base for displaying the number (10 for decimal, 16 for hexadecimal).

    Returns:
        tuple: A tuple containing the size of the integer (2) and the integer value."""
    return print_num(data, offset, description, 2, base)

def print_byte(data, offset, description, base=10):
    """
    Outputs a 1-byte integer value from the byte array at the specified offset.

    Args:
        data (bytes): The byte array containing the data.
        offset (int): The offset in the byte array where the byte value starts.
        description (str): A description of the byte value being displayed.
        base (int): The base for displaying the number (10 for decimal, 16 for hexadecimal).

    Returns:
        tuple: A tuple containing the size of the byte (1) and the byte value.
    """
    return print_num(data, offset, description, 1, base)

def print_string(data, offset, length, description):
    """
    Outputs a string value from the byte array at the specified offset.
    
    Args:
        data (bytes): The byte array containing the data.
        offset (int): The offset in the byte array where the string starts.
        length (int): The length of the string in bytes.
        description (str): A description of the string being displayed.
        
    Returns:
        tuple: A tuple containing the size of the string (length) and the string value.
    """
    value = data[offset:offset+length].decode('ascii')

    string_fragments = [ f"{get_line_start(data, offset, length)} {description}:" ]
    string_fragments.append(value)
    print(" ".join(string_fragments))
    return length, value

def parse_ech_config(base64_ech):
    """
    Parses an Encrypted Client Hello (ECH) configuration from a base64-encoded string.
    Args:
        base64_ech (str): Base64-encoded ECH configuration string.
    """
    full_ech_config = base64.b64decode(base64_ech)
    print(f"Base64 ECH config data: {base64_ech}")
    print(f"Decoded ECH config data (hex): {full_ech_config.hex()}")

    offset = 0 
    offset += print_int(full_ech_config, offset, "Total length of ECH config")[0]

    # There may be many ECH configurations, so go through them all in a loop until we run out of data
    while offset < len(full_ech_config):
        
        offset += print_int(full_ech_config, offset, "ECH Version", base=16)[0]
        
        intsize, config_length = print_int(full_ech_config, offset, "Config length")
        offset += intsize

        config = full_ech_config[offset:offset+config_length]
        curr_pos = 0 # Within the config

        # Start ECHConfig Content

        # Start HpkeKeyConfig

        # uint8 config_id
        curr_pos += print_byte(config, curr_pos, "Config ID")[0]

        # uint16 hpke_kem_id
        hpke_kem_id = int.from_bytes(config[curr_pos:curr_pos+2], 'big')
        print(f"{get_line_start(config,curr_pos, 2)} HPKE KEM ID: {hpke_kem_id:#06x} ({HPKE_KEM_IDS.get(hpke_kem_id, 'Unknown')})")
        curr_pos += 2

        # opaque public_key<1..2^16-1>
        inc, public_key_len = print_int(config, curr_pos, "Public Key Length")
        curr_pos += inc
        print(f"{get_line_start(config, curr_pos, public_key_len)} {HPKE_KEM_IDS.get(hpke_kem_id)} Public Key ({public_key_len} bytes)")
        curr_pos += public_key_len

        # HPKE Cipher Suites are an array, starting with a uint16 length
        cipher_suites_len = int.from_bytes(config[curr_pos:curr_pos+2], 'big')
        inc, cipher_suites_len = print_int(config, curr_pos, "Cipher suites length (bytes)")
        curr_pos += inc

        # Parse cipher suites, each is 2 x uint16: KDF_ID and AEAD_ID
        for cipher_suite in range(cipher_suites_len // 4):
            kdf_id = int.from_bytes(config[curr_pos:curr_pos+2], 'big')
            curr_pos += 2
            aead_id = int.from_bytes(config[curr_pos:curr_pos+2], 'big')
            curr_pos += 2
            print(f"{get_line_start(config, curr_pos-4, 4)} Cipher Suite ({cipher_suite + 1}/{ cipher_suites_len // 4 }): {HPKE_KDF_IDS.get(kdf_id, 'Unknown')} (0x{kdf_id:04x}), {HPKE_AEAD_IDS.get(aead_id, 'Unknown')} (0x{aead_id:04x})")

        # Parse maximum name length
        curr_pos += print_byte(config, curr_pos, "Maximum Name Length")[0]

        # Parse public name
        inc, public_name_length = print_byte(config, curr_pos, "Public Name Length")
        curr_pos += inc
        curr_pos += print_string(config, curr_pos, public_name_length, "Public Name")[0]

        # Parse extensions if any remain
        curr_pos += print_int(config, curr_pos, "Extensions length (bytes)")[0]
        ext_count = 1
        while curr_pos < len(config):
            curr_pos += print_int(config, curr_pos, "Extension Type {ext_count}", base=16)[0]
            inc, ext_len = print_int(config, curr_pos, "Extension Length {ext_count} (bytes)")
            curr_pos += inc
            print(f"{get_line_start(config, curr_pos, ext_len, "Extension Data")})")
            ext_count += 1
        
        
        # Move on to the next ECH config
        offset += config_length

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        print("Usage: python ech-parse.py <base64_string>+")
        print("\nSome sample configurations you could use:")
        print("\tAEX+DQBBqwAgACAWmqqRLIYgCnHZzR0GZZt0CxVV36wykoJXW4STpaHiBAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=")
        print("\tAEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA=" )
        print("\tAEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA" )
        sys.exit(1)
    for arg in sys.argv[1:]:
        parse_ech_config(arg)

