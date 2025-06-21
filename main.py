import argparse
import logging
import os
import hashlib
import zipfile
import pefile
import yara
import filetype

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# YARA rules directory (can be changed via command line)
DEFAULT_YARA_RULES_DIR = "yara_rules"

def calculate_entropy(data):
    """Calculates the entropy of a byte string.

    Args:
        data: The byte string to analyze.

    Returns:
        The entropy of the byte string.
    """
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def detect_embedded_zip(file_path):
    """Detects if a file contains an embedded ZIP archive.

    Args:
        file_path: The path to the file to analyze.

    Returns:
        True if an embedded ZIP archive is found, False otherwise.
    """
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            if b"PK\x03\x04" in content: # ZIP file signature
                return True
    except Exception as e:
        logging.error(f"Error detecting embedded ZIP in {file_path}: {e}")
        return False
    return False


def detect_long_strings(file_path, min_length=50):
    """Detects unusually long strings in a file.

    Args:
        file_path: The path to the file to analyze.
        min_length: The minimum length for a string to be considered long.

    Returns:
        A list of long strings found in the file.
    """
    long_strings = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
            # Decode as UTF-8, ignore errors for non-text files
            try:
                text = content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError as e:
                logging.warning(f"UnicodeDecodeError decoding {file_path}: {e}")
                text = content.decode('latin-1', errors='ignore') # Try latin-1 as fallback

            
            current_string = ""
            for char in text:
                if char.isprintable():
                    current_string += char
                else:
                    if len(current_string) >= min_length:
                        long_strings.append(current_string)
                    current_string = ""
            # Check for a long string at the end
            if len(current_string) >= min_length:
                long_strings.append(current_string)

    except Exception as e:
        logging.error(f"Error detecting long strings in {file_path}: {e}")
    return long_strings


def analyze_file_header(file_path):
    """Analyzes the file header based on magic number.

    Args:
        file_path: The path to the file to analyze.

    Returns:
        A string describing the detected file type based on magic number,
        or None if the file type cannot be determined.
    """
    try:
        kind = filetype.guess(file_path)
        if kind is not None:
            return f"File type: {kind.mime}"
        else:
            return "File type: Unknown"

    except Exception as e:
        logging.error(f"Error analyzing file header of {file_path}: {e}")
        return "File type: Unknown"
    

def scan_with_yara(file_path, yara_rules_dir):
    """Scans a file with YARA rules.

    Args:
        file_path: The path to the file to scan.
        yara_rules_dir: The directory containing the YARA rules.

    Returns:
        A list of YARA matches, or an empty list if no matches are found.
    """
    matches = []
    try:
        rules = compile_yara_rules(yara_rules_dir)
        if rules:
            matches = rules.match(file_path)
        else:
            logging.warning("No YARA rules loaded. Skipping YARA scan.")
    except yara.Error as e:
        logging.error(f"YARA error scanning {file_path}: {e}")
    except Exception as e:
        logging.error(f"Error scanning {file_path} with YARA: {e}")
    return matches


def compile_yara_rules(yara_rules_dir):
    """Compiles YARA rules from a directory.

    Args:
        yara_rules_dir: The directory containing the YARA rules.

    Returns:
        A compiled YARA rules object, or None if an error occurs.
    """
    try:
        rules = {}
        for filename in os.listdir(yara_rules_dir):
            if filename.endswith(".yar") or filename.endswith(".yara"):
                filepath = os.path.join(yara_rules_dir, filename)
                try:
                    rules[filename] = filepath
                except Exception as e:
                    logging.error(f"Error compiling YARA rule {filename}: {e}")
                    return None

        if rules:
            return yara.compile(filepaths=rules)
        else:
            logging.warning(f"No YARA rules found in directory: {yara_rules_dir}")
            return None
    except yara.Error as e:
        logging.error(f"YARA compilation error: {e}")
        return None
    except Exception as e:
        logging.error(f"Error compiling YARA rules: {e}")
        return None


def setup_argparse():
    """Sets up the command-line argument parser.

    Returns:
        An argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(description="Scans files for suspicious characteristics.")
    parser.add_argument("file_path", help="The path to the file to scan.")
    parser.add_argument("--yara-rules-dir", default=DEFAULT_YARA_RULES_DIR, help="The directory containing YARA rules. Default: yara_rules")
    parser.add_argument("--entropy-threshold", type=float, default=6.0, help="Threshold for considering entropy as high. Default: 6.0")
    parser.add_argument("--min-string-length", type=int, default=50, help="Minimum length for considering strings as long. Default: 50")

    return parser

def main():
    """Main function to execute the file scanner."""
    parser = setup_argparse()
    args = parser.parse_args()

    file_path = args.file_path
    yara_rules_dir = args.yara_rules_dir
    entropy_threshold = args.entropy_threshold
    min_string_length = args.min_string_length

    # Input validation
    if not os.path.isfile(file_path):
        logging.error(f"Error: File not found: {file_path}")
        return

    if not os.path.isdir(yara_rules_dir):
        logging.warning(f"Warning: YARA rules directory not found: {yara_rules_dir}. Skipping YARA scanning.")
        yara_rules_dir = None # Disable YARA scanning

    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Calculate entropy
        import math
        entropy = calculate_entropy(file_content)
        print(f"Entropy: {entropy}")
        if entropy > entropy_threshold:
            print(f"Suspicious: High entropy detected (>{entropy_threshold})")

        # Detect embedded ZIP archives
        if detect_embedded_zip(file_path):
            print("Suspicious: Embedded ZIP archive detected")

        # Detect long strings
        long_strings = detect_long_strings(file_path, min_string_length)
        if long_strings:
            print("Suspicious: Long strings detected:")
            for string in long_strings:
                print(f"  - {string[:100]}...") # Print first 100 chars

        # Analyze file header
        header_analysis = analyze_file_header(file_path)
        print(header_analysis)
        
        # Scan with YARA
        if yara_rules_dir:
            matches = scan_with_yara(file_path, yara_rules_dir)
            if matches:
                print("YARA Matches:")
                for match in matches:
                    print(f"  - Rule: {match.rule}, Namespace: {match.namespace}")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()