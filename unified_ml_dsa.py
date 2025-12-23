#!/usr/bin/env python3
"""
Unified script to generate ML-DSA-65 key pair, sign a message, and verify the signature.
All data is stored in a single JSON file.
"""

import json
import subprocess
import tempfile
import os
import sys
import base64


def hex_to_der_ml_dsa_pk(hex_pk):
    """Convert raw public key hex to DER format for ML-DSA-65 - using manual DER construction"""
    # Convert hex string to bytes
    pk_bytes = bytes.fromhex(hex_pk)
    
    # The public key length should be 1952 bytes for ML-DSA-65
    if len(pk_bytes) != 1952:
        print(f"Warning: Public key length is {len(pk_bytes)}, expected 1952 bytes")
    
    # Build the DER structure for ML-DSA public key
    # SEQUENCE {
    #   SEQUENCE {
    #     OBJECT IDENTIFIER 2.16.840.1.101.3.4.3.18 (ML-DSA-65)
    #   }
    #   BIT STRING {
    #     # Raw public key data
    #   }
    # }
    
    # OID for ML-DSA-65: 2.16.840.1.101.3.4.3.18
    oid_ml_dsa_65 = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])
    
    # SEQUENCE for algorithm identifier (OID only, no parameters)
    alg_seq_content = oid_ml_dsa_65
    alg_seq_len = len(alg_seq_content)
    
    if alg_seq_len < 0x80:
        alg_seq = bytes([0x30, alg_seq_len]) + alg_seq_content  # 0x30 = SEQUENCE tag
    else:
        # For longer lengths
        length_bytes = alg_seq_len.to_bytes((alg_seq_len.bit_length() + 7) // 8, 'big')
        alg_seq = bytes([0x30, 0x80 + len(length_bytes)]) + length_bytes + alg_seq_content
    
    # BIT STRING containing the public key (with 0 unused bits)
    # BIT STRING tag is 0x03, then length, then 0x00 for unused bits, then the key
    pk_bitstring_content = bytes([0x00]) + pk_bytes  # 0x00 indicates 0 unused bits
    pk_bitstring_len = len(pk_bitstring_content)
    
    if pk_bitstring_len < 0x80:
        pk_bitstring = bytes([0x03, pk_bitstring_len]) + pk_bitstring_content  # 0x03 = BIT STRING tag
    else:
        # For longer lengths
        length_bytes = pk_bitstring_len.to_bytes((pk_bitstring_len.bit_length() + 7) // 8, 'big')
        pk_bitstring = bytes([0x03, 0x80 + len(length_bytes)]) + length_bytes + pk_bitstring_content
    
    # Combine algorithm identifier and public key
    spki_content = alg_seq + pk_bitstring
    
    # Add outer SEQUENCE for SubjectPublicKeyInfo
    spki_len = len(spki_content)
    if spki_len < 0x80:
        spki_der = bytes([0x30, spki_len]) + spki_content  # 0x30 = SEQUENCE tag
    else:
        # For longer lengths
        length_bytes = spki_len.to_bytes((spki_len.bit_length() + 7) // 8, 'big')
        spki_der = bytes([0x30, 0x80 + len(length_bytes)]) + length_bytes + spki_content
    
    return spki_der


def der_to_pem(der_bytes, key_type):
    """Convert DER bytes to PEM format"""
    b64_encoded = base64.b64encode(der_bytes).decode('ascii')
    
    if key_type == 'private':
        header = "-----BEGIN PRIVATE KEY-----"
        footer = "-----END PRIVATE KEY-----"
    elif key_type == 'public':
        header = "-----BEGIN PUBLIC KEY-----"
        footer = "-----END PUBLIC KEY-----"
    else:
        raise ValueError("key_type must be 'private' or 'public'")
    
    # Format with 65-character lines as per PEM standard
    pem_lines = [header]
    for i in range(0, len(b64_encoded), 65):
        pem_lines.append(b64_encoded[i:i+65])
    pem_lines.append(footer)
    
    return '\n'.join(pem_lines)


def hex_to_pem_public_key(hex_pk):
    """Convert hex public key to PEM format for ML-DSA"""
    # Convert hex to proper DER structure
    der_data = hex_to_der_ml_dsa_pk(hex_pk)
    
    # Convert DER to PEM
    pem_content = der_to_pem(der_data, 'public')
    
    return pem_content


def generate_keypair_with_seed(seed_hex, output_json_file="ml_dsa_vector.json", keep_files=False):
    """Generate ML-DSA-65 key pair using the provided seed and update the JSON file"""
    print(f"Generating ML-DSA-65 key pair with seed: {seed_hex}")
    
    # Create private key with the specific seed
    private_key_file = "ml_dsa_65_sk_gen.pem"
    cmd_gen_sk = [
        "openssl", "genpkey",
        "-algorithm", "ML-DSA-65",
        "-pkeyopt", f"hexseed:{seed_hex}",
        "-out", private_key_file
    ]
    
    result = subprocess.run(cmd_gen_sk, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error generating private key: {result.stderr}")
        return None, None
    
    # Extract public key from private key
    public_key_file = "ml_dsa_65_pk_gen.pem"
    cmd_gen_pk = [
        "openssl", "pkey",
        "-in", private_key_file,
        "-pubout",
        "-out", public_key_file
    ]
    
    result = subprocess.run(cmd_gen_pk, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error generating public key: {result.stderr}")
        return None, None
    
    print(f"Generated private key: {private_key_file}")
    print(f"Generated public key: {public_key_file}")
    
    # Extract public and private keys in hex format
    public_key_hex = get_public_key_hex(public_key_file)
    private_key_hex = get_private_key_hex(private_key_file)
    
    if not public_key_hex or not private_key_hex:
        print("Failed to extract public or private key hex")
        return None, None
    
    # Load existing data or create new structure
    if os.path.exists(output_json_file):
        with open(output_json_file, 'r') as f:
            data = json.load(f)
    else:
            # Create a new structure following the testGroups format with a single unified test
        data = {
            "vsId": 43,
            "algorithm": "ML-DSA",
            "mode": "unified",
            "revision": "FIPS204",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "parameterSet": "ML-DSA-65",
                    "deterministic": True,
                    "signatureInterface": "external",
                    "preHash": "pure",
                    "externalMu": False,
                    "cornerCase": "none",
                    "tests": [
                        {
                            "tcId": 1,
                            "deferred": False,
                            "message": "",
                            "rnd": seed_hex,
                            "pk": public_key_hex,
                            "sk": private_key_hex,
                            "context": "",
                            "hashAlg": "none",
                            "signature": "",
                            "verification_result": False
                        }
                    ]
                }
            ]
        }
    
    # Ensure the testGroups structure exists with only one group
    if "testGroups" not in data:
        data["testGroups"] = []
            
    # Ensure we have only one test group
    if not data["testGroups"]:
        # Create a new unified group if none exists
        unified_group = {
            "tgId": 1,
            "testType": "AFT",
            "parameterSet": "ML-DSA-65",
            "deterministic": True,
            "signatureInterface": "external",
            "preHash": "pure",
            "externalMu": False,
            "cornerCase": "none",
            "tests": []
        }
        data["testGroups"] = [unified_group]
    else:
        # Use the first group and ensure there's only one
        unified_group = data["testGroups"][0]
        data["testGroups"] = [unified_group]
            
    # Check if there's already a test in this group
    if unified_group["tests"]:
        unified_test = unified_group["tests"][0]  # Use the first test for all data
    else:
        # Add a new unified test
        unified_test = {
            "tcId": 1,
            "deferred": False,
            "message": "",
            "rnd": seed_hex,
            "pk": public_key_hex,
            "sk": private_key_hex,
            "context": "",
            "hashAlg": "none",
            "signature": "",
            "verification_result": False
        }
        unified_group["tests"] = [unified_test]
            
    # Update the keyGen data in the unified test
    unified_test["rnd"] = seed_hex
    unified_test["pk"] = public_key_hex
    unified_test["sk"] = private_key_hex
    
    # Remove any old testData structure
    if "testData" in data:
        del data["testData"]
    
    # Save the updated data
    with open(output_json_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Key generation data saved to {output_json_file}")
    
    # If keep_files is False, clean up the generated key files
    if not keep_files:
        if os.path.exists(private_key_file):
            os.remove(private_key_file)
            print(f"Removed temporary private key file: {private_key_file}")
        if os.path.exists(public_key_file):
            os.remove(public_key_file)
            print(f"Removed temporary public key file: {public_key_file}")
    else:
        print(f"Kept key files: {private_key_file}, {public_key_file}")
    
    return private_key_file, public_key_file, public_key_hex, private_key_hex


def get_public_key_hex(public_key_file):
    """Extract the public key in hex format from the PEM file"""
    # Read the public key file and convert it to the raw hex format
    # We'll use the same method as the verification script to ensure compatibility
    
    # Read the public key file
    with open(public_key_file, 'r') as f:
        pem_content = f.read()
    
    # Extract the Base64 content from the PEM format
    lines = pem_content.strip().split('\n')
    b64_content = ''.join(lines[1:-1])  # Remove BEGIN and END lines
    der_bytes = base64.b64decode(b64_content)
    
    # Now we need to extract the actual public key from the DER structure
    # The DER structure is: SEQUENCE { SEQUENCE { OID + NULL }, BIT STRING { public key } }
    # We need to parse this to extract the raw public key
    
    # Find the position where the BIT STRING starts (tag 0x03)
    # and extract the public key from it
    bit_string_tag = 0x03
    pos = 0
    
    # Parse the outer SEQUENCE
    if der_bytes[pos] != 0x30:  # SEQUENCE tag
        print("Error: Not a valid SEQUENCE")
        return None
    pos += 1
    
    # Skip the length of the outer SEQUENCE
    length = der_bytes[pos]
    pos += 1
    if length & 0x80:  # Long form
        num_length_bytes = length & 0x7F
        length = int.from_bytes(der_bytes[pos:pos+num_length_bytes], 'big')
        pos += num_length_bytes
    
    # Now find the BIT STRING inside
    while pos < len(der_bytes):
        if der_bytes[pos] == bit_string_tag:  # BIT STRING tag
            pos += 1
            bit_string_length = der_bytes[pos]
            pos += 1
            if bit_string_length & 0x80:  # Long form
                num_length_bytes = bit_string_length & 0x7F
                bit_string_length = int.from_bytes(der_bytes[pos:pos+num_length_bytes], 'big')
                pos += num_length_bytes
            
            # Skip the 'unused bits' byte (usually 0x00)
            unused_bits = der_bytes[pos]
            pos += 1
            
            # The remaining bytes are the actual public key
            raw_public_key = der_bytes[pos:pos + bit_string_length - 1]
            
            # For ML-DSA-65, the public key should be 1952 bytes
            if len(raw_public_key) != 1952:
                print(f"Warning: Expected 1952 bytes, got {len(raw_public_key)} bytes")
            
            return raw_public_key.hex()
        else:
            # Skip this field
            tag = der_bytes[pos]
            pos += 1
            length = der_bytes[pos]
            pos += 1
            if length & 0x80:  # Long form
                num_length_bytes = length & 0x7F
                length = int.from_bytes(der_bytes[pos:pos+num_length_bytes], 'big')
                pos += num_length_bytes
            pos += length
    
    print("Error: Could not find BIT STRING in DER")
    return None


def get_private_key_hex(private_key_file):
    """Extract the private key in hex format from the PEM file"""
    # Read the private key file and convert it to the raw hex format
    # For ML-DSA, we need to extract the raw private key value from the DER structure
    
    # Read the private key file
    with open(private_key_file, 'r') as f:
        pem_content = f.read()
    
    # Extract the Base64 content from the PEM format
    lines = pem_content.strip().split('\n')
    b64_content = ''.join(lines[1:-1])  # Remove BEGIN and END lines
    der_bytes = base64.b64decode(b64_content)
    
    # Parse the PKCS#8 PrivateKeyInfo structure:
    # SEQUENCE {
    #   INTEGER version
    #   SEQUENCE {
    #     OBJECT IDENTIFIER
    #     NULL (optional)
    #   }
    #   OCTET STRING { raw private key }
    # }
    
    pos = 0
    
    # Check for outer SEQUENCE tag
    if der_bytes[pos] != 0x30:  # SEQUENCE tag
        print("Error: Not a valid SEQUENCE for private key")
        return None
    pos += 1
    
    # Skip the length of the outer SEQUENCE
    length = der_bytes[pos]
    pos += 1
    if length & 0x80:  # Long form
        num_length_bytes = length & 0x7F
        length = int.from_bytes(der_bytes[pos:pos+num_length_bytes], 'big')
        pos += num_length_bytes
    
    # Skip version INTEGER (should be 0)
    if der_bytes[pos] != 0x02:  # INTEGER tag
        print(f"Error: Expected INTEGER tag for version, got {der_bytes[pos]:02x}")
        return None
    pos += 1
    int_length = der_bytes[pos]
    pos += 1
    if int_length & 0x80:  # Long form
        num_length_bytes = int_length & 0x7F
        int_length = int.from_bytes(der_bytes[pos:pos+num_length_bytes], 'big')
        pos += num_length_bytes
    pos += int_length  # Skip the integer value
    
    # Skip algorithm identifier SEQUENCE
    if der_bytes[pos] != 0x30:  # SEQUENCE tag
        print(f"Error: Expected SEQUENCE for algorithm, got {der_bytes[pos]:02x}")
        return None
    pos += 1
    alg_length = der_bytes[pos]
    pos += 1
    if alg_length & 0x80:  # Long form
        num_length_bytes = alg_length & 0x7F
        alg_length = int.from_bytes(der_bytes[pos:pos+num_length_bytes], 'big')
        pos += num_length_bytes
    pos += alg_length  # Skip the algorithm identifier
    
    # Now we should be at the OCTET STRING containing the raw private key
    if der_bytes[pos] != 0x04:  # OCTET STRING tag
        print(f"Error: Expected OCTET STRING for private key, got {der_bytes[pos]:02x}")
        return None
    pos += 1
    octet_length = der_bytes[pos]
    pos += 1
    if octet_length & 0x80:  # Long form
        num_length_bytes = octet_length & 0x7F
        octet_length = int.from_bytes(der_bytes[pos:pos+num_length_bytes], 'big')
        pos += num_length_bytes
    
    # The remaining bytes are the raw private key in its own structure
    raw_private_key = der_bytes[pos:pos + octet_length]
    
    # Parse the raw private key structure (ML-DSA specific)
    # This is another SEQUENCE with the actual private key value
    if raw_private_key[0] != 0x30:  # SEQUENCE tag
        print(f"Error: Expected SEQUENCE in raw private key, got {raw_private_key[0]:02x}")
        return None
    
    # Parse the inner structure to extract the actual private key bytes
    # For ML-DSA-65, the private key is typically 32 bytes (seed) + public key (1952 bytes) + other data
    # The exact structure can vary, so let's extract what's inside the OCTET STRING
    
    # For now, let's just return the full content of the OCTET STRING
    # which contains the ML-DSA private key structure
    return raw_private_key.hex()


def sign_message_with_context(message_hex, private_key_file, context_hex, seed_hex, output_json_file="ml_dsa_vector.json", keep_files=False, public_key_hex=None):
    """Sign a message using the private key with context and update the JSON file"""
    print(f"Signing message with context...")
    
    # Create temporary files for message and signature
    msg_file_path = None
    sig_file_path = None
    
    try:
        # Create message file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.msg') as msg_file:
            msg_file.write(bytes.fromhex(message_hex))
            msg_file_path = msg_file.name
        
        # Create signature output file
        sig_file_path = msg_file_path + '.sig'
        
        # Build the OpenSSL command for signing
        cmd = [
            'openssl', 'pkeyutl', '-sign',
            '-inkey', private_key_file,
            '-in', msg_file_path,
            '-out', sig_file_path
        ]
        
        # Add context if provided
        if context_hex:
            cmd.extend(['-pkeyopt', f'hexcontext-string:{context_hex}'])
        
        # Execute the signing command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error during signing: {result.stderr}")
            return None
        
        # Read the signature from the output file
        with open(sig_file_path, 'rb') as sig_file:
            signature_bytes = sig_file.read()
            signature_hex = signature_bytes.hex()
        
        print(f"Signature generated successfully")
        
        # If public key hex wasn't passed in, extract it from the private key file
        if not public_key_hex:
            public_key_file = "temp_pk.pem"
            cmd_gen_pk = [
                "openssl", "pkey",
                "-in", private_key_file,
                "-pubout",
                "-out", public_key_file
            ]
            
            result = subprocess.run(cmd_gen_pk, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error generating public key for signature record: {result.stderr}")
                return None
            
            public_key_hex = get_public_key_hex(public_key_file)
            os.remove(public_key_file)  # Clean up temporary public key file
            
            if not public_key_hex:
                print("Failed to extract public key hex for signature record")
                return None
        
        # Load existing data from JSON file
        if os.path.exists(output_json_file):
            with open(output_json_file, 'r') as f:
                data = json.load(f)
        else:
            # Create a new structure following the testGroups format with a single unified test
            data = {
                "vsId": 43,
                "algorithm": "ML-DSA",
                "mode": "unified",
                "revision": "FIPS204",
                "isSample": True,
                "testGroups": [
                    {
                        "tgId": 1,
                        "testType": "AFT",
                        "parameterSet": "ML-DSA-65",
                        "deterministic": True,
                        "signatureInterface": "external",
                        "preHash": "pure",
                        "externalMu": False,
                        "cornerCase": "none",
                        "tests": [
                            {
                                "tcId": 1,
                                "deferred": False,
                                "message": message_hex,
                                "rnd": seed_hex,
                                "pk": public_key_hex,
                                "sk": "",
                                "context": context_hex,
                                "hashAlg": "none",
                                "signature": signature_hex,
                                "verification_result": False
                            }
                        ]
                    }
                ]
            }
        
        # Ensure the testGroups structure exists with only one group
        if "testGroups" not in data:
            data["testGroups"] = []
        
        # Ensure we have only one test group
        if not data["testGroups"]:
            # Create a new unified group if none exists
            unified_group = {
                "tgId": 1,
                "testType": "AFT",
                "parameterSet": "ML-DSA-65",
                "deterministic": True,
                "signatureInterface": "external",
                "preHash": "pure",
                "externalMu": False,
                "cornerCase": "none",
                "tests": []
            }
            data["testGroups"] = [unified_group]
        else:
            # Use the first group and ensure there's only one
            unified_group = data["testGroups"][0]
            data["testGroups"] = [unified_group]
        
        # Check if there's already a test in this group
        if unified_group["tests"]:
            unified_test = unified_group["tests"][0]  # Use the first test for all data
        else:
            # Add a new unified test
            unified_test = {
                "tcId": 1,
                "deferred": False,
                "message": message_hex,
                "rnd": seed_hex,
                "pk": public_key_hex,
                "sk": "",
                "context": context_hex,
                "hashAlg": "none",
                "signature": signature_hex,
                "verification_result": False
            }
            unified_group["tests"] = [unified_test]
        
        # Update the sigGen data in the unified test
        unified_test["message"] = message_hex
        unified_test["pk"] = public_key_hex
        unified_test["context"] = context_hex
        unified_test["signature"] = signature_hex
        unified_test["rnd"] = seed_hex
        
        # Remove any old testData structure
        if "testData" in data:
            del data["testData"]
        
        # Save the updated data
        with open(output_json_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Signature data saved to {output_json_file}")
        
        # If keep_files is True, preserve the message and signature files
        if not keep_files:
            # Clean up temporary files
            for temp_path in [msg_file_path, sig_file_path]:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            print(f"Kept temporary files: {msg_file_path}, {sig_file_path}")
        
        return signature_hex
        
    except Exception as e:
        print(f"Error during signing: {str(e)}")
        # Clean up in case of exception
        for temp_path in [msg_file_path, sig_file_path]:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        return None


def verify_signature_with_openssl(message_hex, signature_hex, public_key_pem, context_hex="", keep_files=False):
    """Verify ML-DSA signature using OpenSSL CLI with optional context"""
    
    # Create temporary files
    msg_file_path = None
    sig_file_path = None
    pubkey_file_path = None
    
    try:
        # Create message file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.msg') as msg_file:
            # Write the message in binary format
            msg_file.write(bytes.fromhex(message_hex))
            msg_file_path = msg_file.name
        
        # Create signature file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.sig') as sig_file:
            # Write the signature in binary format
            sig_file.write(bytes.fromhex(signature_hex))
            sig_file_path = sig_file.name
        
        # Create public key file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pubkey.pem') as pubkey_file:
            pubkey_file.write(public_key_pem)
            pubkey_file_path = pubkey_file.name
        
        # Build the OpenSSL command
        cmd = [
            'openssl', 'pkeyutl', '-verify', 
            '-pubin', '-inkey', pubkey_file_path,
            '-in', msg_file_path,
            '-sigfile', sig_file_path
        ]
        
        # Add context if provided
        if context_hex:
            # Use hexcontext-string to pass the context in hex format
            cmd.extend(['-pkeyopt', f'hexcontext-string:{context_hex}'])
        
        # Use OpenSSL to verify the signature
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if verification was successful
        success = result.returncode == 0
        if not success:
            print(f"OpenSSL verification failed: {result.stderr}")
        
        # If keep_files is True, preserve the temporary files
        if not keep_files:
            # Clean up temporary files
            for temp_path in [msg_file_path, sig_file_path, pubkey_file_path]:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            print(f"Kept temporary files: {msg_file_path}, {sig_file_path}, {pubkey_file_path}")
        
        return success
        
    except Exception as e:
        print(f"Error during verification: {str(e)}")
        # Clean up in case of exception
        for temp_path in [msg_file_path, sig_file_path, pubkey_file_path]:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        return False


def verify_signature_with_context(message_hex, signature_hex, public_key_hex, context_hex="", seed_hex="", output_json_file="ml_dsa_vector.json", keep_files=False):
    """Verify a signature using the public key with context and update the JSON file"""
    print(f"Verifying signature with context...")
    
    # Convert public key from hex to PEM
    public_key_pem = hex_to_pem_public_key(public_key_hex)
    
    # Verify the signature with context if available
    is_valid = verify_signature_with_openssl(message_hex, signature_hex, public_key_pem, context_hex, keep_files)
    
    if is_valid:
        print("Signature verification: SUCCESS")
    else:
        print("Signature verification: FAILED")
    
    # Load existing data from JSON file
    if os.path.exists(output_json_file):
        with open(output_json_file, 'r') as f:
            data = json.load(f)
    else:
        # Create a new structure following the testGroups format with a single unified test
        data = {
            "vsId": 43,
            "algorithm": "ML-DSA",
            "mode": "unified",
            "revision": "FIPS204",
            "isSample": True,
            "testGroups": [
                {
                    "tgId": 1,
                    "testType": "AFT",
                    "parameterSet": "ML-DSA-65",
                    "deterministic": True,
                    "signatureInterface": "external",
                    "preHash": "pure",
                    "externalMu": False,
                    "cornerCase": "none",
                    "tests": [
                        {
                            "tcId": 1,
                            "deferred": False,
                            "message": message_hex,
                            "rnd": seed_hex,
                            "pk": public_key_hex,
                            "sk": "",
                            "context": context_hex,
                            "hashAlg": "none",
                            "signature": signature_hex,
                            "verification_result": is_valid
                        }
                    ]
                }
            ]
        }
    
    # Ensure the testGroups structure exists with only one group
    if "testGroups" not in data:
        data["testGroups"] = []
    
    # Ensure we have only one test group
    if not data["testGroups"]:
        # Create a new unified group if none exists
        unified_group = {
            "tgId": 1,
            "testType": "AFT",
            "parameterSet": "ML-DSA-65",
            "deterministic": True,
            "signatureInterface": "external",
            "preHash": "pure",
            "externalMu": False,
            "cornerCase": "none",
            "tests": []
        }
        data["testGroups"] = [unified_group]
    else:
        # Use the first group and ensure there's only one
        unified_group = data["testGroups"][0]
        data["testGroups"] = [unified_group]
    
    # Check if there's already a test in this group
    if unified_group["tests"]:
        unified_test = unified_group["tests"][0]  # Use the first test for all data
    else:
        # Add a new unified test
        unified_test = {
            "tcId": 1,
            "deferred": False,
            "message": message_hex,
            "rnd": seed_hex,
            "pk": public_key_hex,
            "sk": "",
            "context": context_hex,
            "hashAlg": "none",
            "signature": signature_hex,
            "verification_result": is_valid
        }
        unified_group["tests"] = [unified_test]
    
    # Update the sigVer data in the unified test
    unified_test["message"] = message_hex
    unified_test["pk"] = public_key_hex
    unified_test["context"] = context_hex
    unified_test["signature"] = signature_hex
    unified_test["verification_result"] = is_valid
    unified_test["rnd"] = seed_hex
    
    # Remove any old testData structure
    if "testData" in data:
        del data["testData"]
    
    # Save the updated data
    with open(output_json_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Verification data saved to {output_json_file}")
    
    return is_valid


def main():
    # Parse command line arguments
    keep_files = False
    output_json_file = "ml_dsa_vector.json"
    seed_hex = "250365DD59ACBA742202CC53D9319C33BACE939D3996B544F64A3EA037E004B5"  # Default seed
    message_hex = "7AA3A939B48A6162F5C2881EDAF1DDA4E23172844A031DE0DD3AA9A338F77D1EFCDCEDF4F1C31D87BA4246FEFAEAFEA6D601BDE15287"
    context_hex = "79CE52A1DCC0BAB5C8590B5398D0108890150D17BF190778A4419D136182CD2E556424EABA2D48C8E552B7400F5985935DA023050E5A199DB80DCE2488A0087F991AAD1D646E29B41A1C71D9B7BF85726625B46A02664802828858E3E162E4572C6E0094CBEBB9110A256C575D9B2611F0AF876CF734EE99AF78091D8033DA8674CF75DED17621ED92AB9FF0FFF87B8BA6D917BBE95826A14DD10AEDD94CBDA9166B4FD927CDEA076B70C51DD63B6ABA66E269"
    
    # Check if command line arguments are provided
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg == "--keep-files":
                keep_files = True
            elif arg.startswith("--output="):
                output_json_file = arg.split("=", 1)[1]
            elif arg.startswith("--seed="):
                seed_hex = arg.split("=", 1)[1]
            elif arg.startswith("--message="):
                message_hex = arg.split("=", 1)[1]
            elif arg.startswith("--context="):
                context_hex = arg.split("=", 1)[1]
            else:
                print(f"Usage: python unified_ml_dsa.py [--seed=SEED_HEX] [--message=MESSAGE_HEX] [--context=CONTEXT_HEX] [--output=OUTPUT_JSON_FILE] [--keep-files]")
                print("Example: python unified_ml_dsa.py --seed=250365DD59ACBA742202CC53D9319C33BACE939D3996B544F64A3EA037E004B5 --message=7AA3A939B48A6162F5C2881EDAF1DDA4E23172844A031DE0DD3AA9A338F77D1EFCDCEDF4F1C31D87BA4246FEFAEAFEA6D601BDE15287 --context=79CE52A1DCC0BAB5C8590B5398D0108890150D17BF190778A4419D136182CD2E556424EABA2D48C8E552B7400F5985935DA023050E5A199DB80DCE2488A0087F991AAD1D646E29B41A1C71D9B7BF85726625B46A02664802828858E3E162E4572C6E0094CBEBB9110A256C575D9B2611F0AF876CF734EE99AF78091D8033DA8674CF75DED17621ED92AB9FF0FFF87B8BA6D917BBE95826A14DD10AEDD94CBDA9166B4FD927CDEA076B70C51DD63B6ABA66E269 --output=ml_dsa_vector.json [--keep-files]")
                return 1
    
    print("Step 1: Generating key pair with the provided seed...")
    result = generate_keypair_with_seed(seed_hex, output_json_file, keep_files=True)  # Always keep files for signing step
    
    if not result or len(result) < 4:
        print("Failed to generate key pair")
        return 1
    
    private_key_file, public_key_file, public_key_hex, private_key_hex = result
    
    print("\nStep 2: Signing the message with context...")
    signature_hex = sign_message_with_context(message_hex, private_key_file, context_hex, seed_hex, output_json_file, keep_files, public_key_hex)
    
    # Clean up key files after signing if not keeping them
    if not keep_files:
        if private_key_file and os.path.exists(private_key_file):
            os.remove(private_key_file)
            print(f"Removed temporary private key file: {private_key_file}")
        if public_key_file and os.path.exists(public_key_file):
            os.remove(public_key_file)
            print(f"Removed temporary public key file: {public_key_file}")
    
    if not signature_hex:
        print("Failed to generate signature")
        return 1
    
    print(f"Generated signature: {signature_hex[:64]}...")  # Show first 64 chars
    
    print("\nStep 3: Verifying the signature...")
    is_valid = verify_signature_with_context(message_hex, signature_hex, public_key_hex, context_hex, seed_hex, output_json_file, keep_files)
    
    # Ensure the mode is unified and consolidate all data into a single test
    if os.path.exists(output_json_file):
        with open(output_json_file, 'r') as f:
            data = json.load(f)
        
        # Ensure we have a single unified test group
        if "testGroups" in data and data["testGroups"]:
            # Take the first test group and consolidate all tests into one
            unified_group = data["testGroups"][0]
            
            if len(unified_group.get("tests", [])) > 1:
                # Consolidate all test data into the first test
                first_test = unified_group["tests"][0]
                for test in unified_group["tests"][1:]:
                    # Merge all fields from other tests into the first test
                    for key, value in test.items():
                        if key != "tcId":  # Keep tcId from the first test
                            first_test[key] = value
                
                # Keep only the first test
                unified_group["tests"] = [first_test]
        
        # Set mode to unified
        data["mode"] = "unified"
        
        with open(output_json_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    if is_valid:
        print("\nAll operations completed successfully! Check the JSON file for results.")
        return 0
    else:
        print("\nVerification failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())