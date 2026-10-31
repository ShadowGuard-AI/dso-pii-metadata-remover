![Banner](banner.png)

# dso-pii-metadata-remover
Plain text tool: replaces PII patterns in the text content of plain text files. It does not read PDF, DOCX, or XLSX files, and it does not read or edit file metadata. The name is kept for continuity; the scope is plain text only.

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-pii-metadata-remover`

## Usage
`python3 main.py input.txt output.txt`

The output file argument is required, and an output path that resolves to the input file is refused at exit 1.

## What it replaces
- Email addresses, replaced with [REDACTED_EMAIL]
- Standalone domain names, replaced with [REDACTED_DOMAIN]
- Phone numbers in plain, parenthesised, and +1 forms, replaced with [REDACTED_PHONE]
- US SSN shaped identifiers (123-45-6789 shape), replaced with [REDACTED_IDENTIFIER]

Replacement counts are logged by class; the original values are never logged. A run that replaces nothing exits 1, prints no success line, and writes no output file.

## Parameters
- `-h`: Show help message and exit
- `-l`: Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.

## License
Copyright (c) ShadowStrikeHQ
