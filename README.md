# ac-SuspiciousFileScanner
Scans files for indicators of suspicious characteristics such as high entropy, embedded resources (e.g., ZIP archives), unusually long strings, or unusual file headers based on magic number analysis. - Focused on Tools for collecting, indexing, and categorizing digital artifacts based on file type, embedded metadata, YARA rules, and other indicators. Useful for incident response and threat intelligence gathering. This differs from analysis as it is largely focused on *organizing* and *cataloging* discovered files.

## Install
`git clone https://github.com/ShadowGuardAI/ac-suspiciousfilescanner`

## Usage
`./ac-suspiciousfilescanner [params]`

## Parameters
- `-h`: Show help message and exit
- `--yara-rules-dir`: The directory containing YARA rules. Default: yara_rules
- `--entropy-threshold`: Threshold for considering entropy as high. Default: 6.0
- `--min-string-length`: Minimum length for considering strings as long. Default: 50

## License
Copyright (c) ShadowGuardAI
