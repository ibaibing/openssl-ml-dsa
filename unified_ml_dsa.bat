@echo off
REM Batch file to run unified ML-DSA operations (key generation, signing, verification) with shared JSON output
REM Usage: unified_ml_dsa.bat [--seed=SEED_HEX] [--message=MESSAGE_HEX] [--context=CONTEXT_HEX] [--output=OUTPUT_JSON_FILE] [--keep-files]

setlocal enabledelayedexpansion

REM Default values
set "SEED=250365DD59ACBA742202CC53D9319C33BACE939D3996B544F64A3EA037E004B5"
set "MESSAGE=7AA3A939B48A6162F5C2881EDAF1DDA4E23172844A031DE0DD3AA9A338F77D1EFCDCEDF4F1C31D87BA4246FEFAEAFEA6D601BDE15287"
set "CONTEXT=79CE52A1DCC0BAB5C8590B5398D0108890150D17BF190778A4419D136182CD2E556424EABA2D48C8E552B7400F5985935DA023050E5A199DB80DCE2488A0087F991AAD1D646E29B41A1C71D9B7BF85726625B46A02664802828858E3E162E4572C6E0094CBEBB9110A256C575D9B2611F0AF876CF734EE99AF78091D8033DA8674CF75DED17621ED92AB9FF0FFF87B8BA6D917BBE95826A14DD10AEDD94CBDA9166B4FD927CDEA076B70C51DD63B6ABA66E269"
set "OUTPUT_JSON_FILE=ml_dsa_vector.json"
set "KEEP_FILES=--keep-files"

REM Parse command line arguments
:parse_args
if "%~1"=="" goto args_parsed

if /i "%~1"=="--keep-files" (
    set "KEEP_FILES=--keep-files"
    shift
    goto parse_args
)

if /i "%~1"=="--seed" (
    set "SEED=%~2"
    shift
    shift
    goto parse_args
)

if /i "%~1"=="--message" (
    set "MESSAGE=%~2"
    shift
    shift
    goto parse_args
)

if /i "%~1"=="--context" (
    set "CONTEXT=%~2"
    shift
    shift
    goto parse_args
)

if /i "%~1"=="--output" (
    set "OUTPUT_JSON_FILE=%~2"
    shift
    shift
    goto parse_args
)

if "%~1"=="--help" (
    echo Usage: %0 [--seed=SEED_HEX] [--message=MESSAGE_HEX] [--context=CONTEXT_HEX] [--output=OUTPUT_JSON_FILE] [--keep-files]
    echo Example: %0 --seed=250365DD59ACBA742202CC53D9319C33BACE939D3996B544F64A3EA037E004B5 --message=7AA3A939B48A6162F5C2881EDAF1DDA4E23172844A031DE0DD3AA9A338F77D1EFCDCEDF4F1C31D87BA4246FEFAEAFEA6D601BDE15287 --context=79CE52A1DCC0BAB5C8590B5398D0108890150D17BF190778A4419D136182CD2E556424EABA2D48C8E552B7400F5985935DA023050E5A199DB80DCE2488A0087F991AAD1D646E29B41A1C71D9B7BF85726625B46A02664802828858E3E162E4572C6E0094CBEBB9110A256C575D9B2611F0AF876CF734EE99AF78091D8033DA8674CF75DED17621ED92AB9FF0FFF87B8BA6D917BBE95826A14DD10AEDD94CBDA9166B4FD927CDEA076B70C51DD63B6ABA66E269 --output=ml_dsa_vector.json --keep-files
    exit /b 0
)

REM Check if argument starts with --seed= format
if "%~1" neq "" (
    set "arg=%~1"
    if "!arg:~0,7!"=="--seed=" (
        set "SEED=!arg:~7!"
        shift
        goto parse_args
    )
    if "!arg:~0,10!"=="--message=" (
        set "MESSAGE=!arg:~10!"
        shift
        goto parse_args
    )
    if "!arg:~0,10!"=="--context=" (
        set "CONTEXT=!arg:~10!"
        shift
        goto parse_args
    )
    if "!arg:~0,9!"=="--output=" (
        set "OUTPUT_JSON_FILE=!arg:~9!"
        shift
        goto parse_args
    )
)

echo Unknown argument: %~1
echo Usage: %0 [--seed=SEED_HEX] [--message=MESSAGE_HEX] [--context=CONTEXT_HEX] [--output=OUTPUT_JSON_FILE] [--keep-files]
exit /b 1

:args_parsed

echo Running unified ML-DSA operations...
echo Seed: !SEED!
echo Message: !MESSAGE:~0,64!...
echo Context: !CONTEXT:~0,64!...
echo Output JSON file: !OUTPUT_JSON_FILE!
if defined KEEP_FILES (
    echo Keep files: Yes
) else (
    echo Keep files: No
)

REM Run the unified script with parameters
if defined KEEP_FILES (
    python unified_ml_dsa.py --seed=!SEED! --message=!MESSAGE! --context=!CONTEXT! --output=!OUTPUT_JSON_FILE! --keep-files
) else (
    python unified_ml_dsa.py --seed=!SEED! --message=!MESSAGE! --context=!CONTEXT! --output=!OUTPUT_JSON_FILE!
)

REM Capture the exit code
set exit_code=!errorlevel!

if !exit_code! equ 0 (
    echo.
    echo Unified ML-DSA operations completed successfully!
    echo Results saved to !OUTPUT_JSON_FILE!
) else (
    echo.
    echo Unified ML-DSA operations failed with exit code !exit_code!.
)

exit /b !exit_code!