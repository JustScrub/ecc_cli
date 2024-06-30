# Benchmarking ECC_CLI
Directory with benchmark scripts of the ECC.py library.    
Benchmarked against the ECpy library from PyPI.

Usage: 
    python bench.py [-c=<csv_output_file>] ... [-l=<latex_table_output_file>] ...

If no arguments provided, prints CSV output to STDIN. Delimiter is semi-colon (;).

For each argument starting with `-c=`, writes CSV output to the file with name specified after equal sign. Delimiter is semi-colon (;).

For each argument starting with `-l=`, writes output as latex table to the file specified after equal sign.