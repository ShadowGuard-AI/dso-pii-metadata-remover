import argparse
import logging
import os
import sys
import chardet
import re
import traceback

# Define global logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Replaces PII patterns in plain text files. Plain text only: it does not read PDF, DOCX, or XLSX files and does not edit file metadata.")
    parser.add_argument("input_file", help="The input file to process.")
    parser.add_argument("output_file", help="The output file to write to.")
    parser.add_argument("-l", "--log_level", help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
                        default="INFO")
    return parser


# Order in this list is load bearing. Each pattern runs over the output of
# the ones before it, so email goes first: the domain pattern below would
# happily eat the host half of an address and leave the local part behind.
# Identifier runs before phone for the same reason, first claim wins.
PATTERNS = [
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    ("identifier", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), "[REDACTED_IDENTIFIER]"),
    ("phone", re.compile(r"(?<!\d)(?:\+?1[\s.\-]?)?(?:\(\d{3}\)\s?|\d{3}[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)"), "[REDACTED_PHONE]"),
    # The TLD list is a fixed shortlist on purpose. A domain under any other
    # TLD passes through untouched, and I accept that gap instead of matching
    # every dotted word in the file.
    ("domain", re.compile(r"\b(?:[A-Za-z0-9\-]+\.)+(?:com|org|net|io|edu|gov|info|biz)\b", re.IGNORECASE), "[REDACTED_DOMAIN]"),
]


def remove_pii_metadata(input_file, output_file):
    """
    Replaces PII patterns in a plain text file. Returns the total replacement count.
    """
    try:
        # Detect file encoding
        with open(input_file, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            encoding = result['encoding']

        # No utf-8 fallback here, unlike some of my other tools. Writing output in
        # a guessed encoding could mangle the untouched text, so I stop instead.
        if not encoding:
            raise ValueError("Failed to detect file encoding.")
        
        # Read the input file with detected encoding
        with open(input_file, 'r', encoding=encoding) as infile:
            content = infile.read()

        total = 0
        for name, pattern, replacement in PATTERNS:
            # subn gives me the count per pattern, which is the only honest basis for
            # the total below and for the nothing-replaced failure after this loop.
            content, n = pattern.subn(replacement, content)
            if n:
                logger.info(f"Replaced {n} {name} value(s).")
            total += n
        if total == 0:
        # Nothing matched, so I write no output file at all. A clean copy of the
        # input sitting next to it would read as a finished sanitization.
            logger.error("No PII patterns found; nothing was replaced.")
            return 0

        with open(output_file, 'w', encoding=encoding) as outfile:
            outfile.write(content)

        logger.info(f"Successfully sanitized {input_file} and wrote to {output_file} ({total} replacement(s))")
        return total

    except FileNotFoundError:
        logger.error(f"Error: Input file not found: {input_file}")
        raise
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        logger.error(traceback.format_exc()) #Include traceback
        raise


def validate_input(input_file, output_file):
    """
    Validates the input parameters.
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file not found: {input_file}")

    # realpath on both sides, so a symlink or a .. spelling of the input path
    # is refused too, not just the identical string. There is no in-place mode
    # in this tool, so there is no sanctioned way around this check.
    if os.path.realpath(output_file) == os.path.realpath(input_file):
        raise ValueError("Output file resolves to the input file; refusing to overwrite it.")

    if os.path.exists(output_file):
        logger.warning(f"Output file {output_file} already exists. It will be overwritten.")
    
    if not os.access(input_file, os.R_OK):
        raise PermissionError(f"Cannot read input file {input_file}. Check permissions.")

    #Basic check if extension is reasonable
    input_ext = os.path.splitext(input_file)[1].lower()
    output_ext = os.path.splitext(output_file)[1].lower()

    # Extension mismatch is a warning, not a refusal. The tool only reads text
    # either way, so a renamed file is the caller's choice to make.
    if input_ext != output_ext:
        logger.warning(f"Input ({input_ext}) and Output ({output_ext}) file extensions differ. Make sure file type is supported")
    
    
    return True


def main():
    """
    Main function to execute the PII metadata removal process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging level
    try:
        # setLevel raises ValueError on an unknown name, which is the only reason
        # this try block exists. argparse was left without choices on purpose, so
        # a typo lands here instead of failing argument parsing.
        logger.setLevel(args.log_level.upper())
    except ValueError:
        logger.error(f"Invalid log level: {args.log_level}.  Using INFO instead.")
        logger.setLevel(logging.INFO)
    
    try:
        validate_input(args.input_file, args.output_file)
        total = remove_pii_metadata(args.input_file, args.output_file)
    except Exception as e:
        logger.error(f"PII removal process failed: {e}")
        sys.exit(1)

    if total == 0:
        logger.error("Nothing was replaced; the run did not complete a sanitization.")
        sys.exit(1)

    logger.info("PII removal process completed.")


if __name__ == "__main__":
    # Usage Examples:
    # python main.py input.txt output.txt
    # python main.py data.txt sanitized_data.txt -l DEBUG
    main()