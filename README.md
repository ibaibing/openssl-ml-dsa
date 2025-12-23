# ML-DSA OpenSSL Integration Suite

A comprehensive Python implementation for generating, signing, and verifying ML-DSA-65 signatures using OpenSSL integration. This project provides a unified workflow for ML-DSA cryptographic operations compliant with FIPS 204 standards.

## Project Overview

This project implements the ML-DSA (Module-Lattice-Based Digital Signature Algorithm) as specified in FIPS 204, providing a complete cryptographic workflow for post-quantum digital signatures. The implementation uses OpenSSL for cryptographic operations while providing a Python interface for easy integration and testing.

## Features

- **Unified Workflow**: Single script handles key generation, message signing, and signature verification
- **FIPS 204 Compliant**: Implementation follows the Federal Information Processing Standards
- **OpenSSL Integration**: Leverages OpenSSL for cryptographic operations
- **JSON Vector Output**: All operations output to a single unified JSON file
- **Context Support**: Full support for signature contexts as specified in the standard
- **PEM/DER Conversion**: Built-in conversion between different key formats

## Prerequisites

- Python 3.7+
- OpenSSL 3.2+ with ML-DSA support
- Windows or Linux environment

## Dependencies

This project uses only Python standard library modules:
- json
- subprocess
- tempfile
- os
- sys
- base64

## Usage

### Command Line Usage

```bash
python unified_ml_dsa.py [--seed=SEED_HEX] [--message=MESSAGE_HEX] [--context=CONTEXT_HEX] [--output=OUTPUT_JSON_FILE] [--keep-files]
```

Example:
```bash
python unified_ml_dsa.py --seed=250365DD59ACBA742202CC53D9319C33BACE939D3996B544F64A3EA037E004B5 --message=7AA3A939B48A6162F5C2881EDAF1DDA4E23172844A031DE0DD3AA9A338F77D1EFCDCEDF4F1C31D87BA4246FEFAEAFEA6D601BDE15287 --context=79CE52A1DCC0BAB5C8590B5398D0108890150D17BF190778A4419D136182CD2E556424EABA2D48C8E552B7400F5985935DA023050E5A199DB80DCE2488A0087F991AAD1D646E29B41A1C71D9B7BF85726625B46A02664802828858E3E162E4572C6E0094CBEBB9110A256C575D9B2611F0AF876CF734EE99AF78091D8033DA8674CF75DED17621ED92AB9FF0FFF87B8BA6D917BBE95826A14DD10AEDD94CBDA9166B4FD927CDEA076B70C51DD63B6ABA66E269 --output=ml_dsa_vector.json --keep-files
```

### Batch File Usage (Windows)

```cmd
unified_ml_dsa.bat
```

## Output Format

The script generates a JSON file with three test groups:
1. **keyGen**: Key generation data
2. **sigGen**: Signature generation data
3. **sigVer**: Signature verification data

Each group contains the relevant cryptographic data in the proper format for testing and validation.

## Key Generation

The script uses a deterministic seed to generate ML-DSA-65 key pairs, ensuring reproducible results for testing purposes.

## Signing and Verification

The implementation supports both message signing and signature verification with optional context, following the ML-DSA standard specifications.

## Temporary Files

When the `--keep-files` option is used, the script preserves temporary .bin and .pem files for external validation using OpenSSL CLI tools.

## License

This project is licensed under the MIT License - see the LICENSE file for details.