Hash Reverser & Generator for Base64 Encoded Numbers

This Python script is designed for penetration testing, particularly focusing on reversing and generating hashes of base64 encoded numbers. It supports multiple hash algorithms (MD5, SHA1, SHA256, SHA512) and allows you to either generate hashes for a range of numbers or attempt to reverse a given hash by checking a range of base64 encoded numbers.
Features

    Reverse Hashing: Given a hash and a hash type, the script attempts to reverse it by testing base64 encoded numbers and comparing the resulting hash to the target.
    Hash Generation: Generates hashes for base64 encoded numbers within a specified range, for different hash algorithms.
    Multithreading: The script uses a thread pool executor to parallelize hash comparisons for faster results.

Supported Hash Types

    MD5
    SHA1
    SHA256
    SHA512

Installation

    Clone the repository:

git clone https://github.com/yourusername/hash-reverser-generator.git
cd hash-reverser-generator

Ensure you have Python 3.x installed. If not, download and install it from python.org.

Install the required dependencies:

    pip install -r requirements.txt

Usage
Reverse Hash Mode

To reverse a hash, use the -R flag and provide the hash value and the desired hash type. The script will try to find the number that corresponds to the given hash.

python script.py -R <hash_value> <hash_type>

    <hash_value>: The hash you want to reverse.
    <hash_type>: The hash algorithm used to generate the hash. Options: md5, sha1, sha256, sha512.

Example:

python script.py -R e99a18c428cb38d5f260853678922e03 md5

This will attempt to reverse the MD5 hash e99a18c428cb38d5f260853678922e03 and find the base64 encoded number that matches it.
Generate Hashes Mode

To generate hashes for a range of base64 encoded numbers, provide the start and end numbers, and specify the hash type. The script will output the generated hashes for each number in the range.

python script.py <hash_type> <start_num> <end_num>

    <hash_type>: The hash algorithm to use. Options: md5, sha1, sha256, sha512.
    <start_num>: The start of the range (inclusive).
    <end_num>: The end of the range (inclusive).

Example:

python script.py sha256 1 10

This will generate the SHA256 hashes for base64 encoded numbers from 1 to 10.
Example Workflow

    Generate hashes for numbers 1 to 1000 with SHA256:

python script.py sha256 1 1000

Reverse a hash:

    python script.py -R <target_hash> sha256

    Where <target_hash> is the hash you want to reverse.

Notes

    The script uses a ThreadPoolExecutor for parallel processing, which allows for faster hash comparison in reverse mode.
    The script assumes that the hash was generated from a base64 encoded number within the provided range.
