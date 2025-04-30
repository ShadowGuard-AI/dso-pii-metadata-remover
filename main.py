import argparse
import logging
import os
import sys
import chardet
import traceback

# Define global logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Removes PII metadata from common file formats.")
    parser.add_argument("input_file", help="The input file to process.")
    parser.add_argument("output_file", help="The output file to write to.")
    parser.add_argument("-l", "--log_level", help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
                        default="INFO")
    return parser


def remove_pii_metadata(input_file, output_file):
    """
    Removes PII metadata from the given input file.
    Currently supports text-based files only.
    """
    try:
        # Detect file encoding
        with open(input_file, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            encoding = result['encoding']

        if not encoding:
            raise ValueError("Failed to detect file encoding.")
        
        # Read the input file with detected encoding
        with open(input_file, 'r', encoding=encoding) as infile:
            content = infile.read()

        # Basic PII removal (replace common patterns with placeholders)
        # NOTE: This is a placeholder implementation.  A proper implementation would use more sophisticated techniques.
        content = content.replace("@example.com", "[REDACTED_EMAIL_DOMAIN]") #Redact email domain.
        content = content.replace("example.com", "[REDACTED_DOMAIN]") #Redact domain.
        
        # Write the sanitized content to the output file
        with open(output_file, 'w', encoding=encoding) as outfile:
            outfile.write(content)

        logger.info(f"Successfully sanitized {input_file} and wrote to {output_file}")

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

    if os.path.exists(output_file):
        logger.warning(f"Output file {output_file} already exists. It will be overwritten.")
    
    if not os.access(input_file, os.R_OK):
        raise PermissionError(f"Cannot read input file {input_file}. Check permissions.")

    #Basic check if extension is reasonable
    input_ext = os.path.splitext(input_file)[1].lower()
    output_ext = os.path.splitext(output_file)[1].lower()

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
        logger.setLevel(args.log_level.upper())
    except ValueError:
        logger.error(f"Invalid log level: {args.log_level}.  Using INFO instead.")
        logger.setLevel(logging.INFO)
    
    try:
        validate_input(args.input_file, args.output_file)
        remove_pii_metadata(args.input_file, args.output_file)
    except Exception as e:
        logger.error(f"PII removal process failed: {e}")
        sys.exit(1)

    logger.info("PII metadata removal process completed.")


if __name__ == "__main__":
    # Usage Examples:
    # python main.py input.txt output.txt
    # python main.py data.txt sanitized_data.txt -l DEBUG
    main()