import hashlib
import base64
import argparse
from concurrent.futures import ThreadPoolExecutor

def try_reverse_hash(target_hash, hash_type, start_num=1, end_num=1000000):
    """Try to reverse a hash by testing base64 encoded numbers"""
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    hash_func = hash_functions[hash_type]
    target_hash = target_hash.lower()
    
    print(f"Attempting to reverse {hash_type} hash: {target_hash}")
    
    def check_number(num):
        b64_num = base64.b64encode(str(num).encode()).decode()
        hashed = hash_func(b64_num.encode()).hexdigest()
        if hashed == target_hash:
            return num, b64_num
        return None
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_number, num) for num in range(start_num, end_num + 1)]
        
        for future in futures:
            result = future.result()
            if result:
                num, b64_num = result
                print(f"\nFound match!")
                print(f"Number: {num}")
                print(f"Base64: {b64_num}")
                print(f"Hash: {target_hash}")
                return

def generate_hashed_b64(start_num, end_num, hash_type):
    """Generate hashes of base64 encoded numbers"""
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    hash_func = hash_functions[hash_type]
    
    print(f"Generating {hash_type} hashes of base64 encoded numbers {start_num}-{end_num}:")
    for num in range(start_num, end_num + 1):
        b64_num = base64.b64encode(str(num).encode()).decode()
        hashed = hash_func(b64_num.encode()).hexdigest()
        print(f"{num} -> base64: {b64_num} -> {hash_type}: {hashed}")

def main():
    parser = argparse.ArgumentParser(description='Generate or reverse hashes of base64 encoded numbers')
    parser.add_argument('-R', '--reverse', action='store_true', help='Reverse hash mode')
    parser.add_argument('hash_type', choices=['md5', 'sha1', 'sha256', 'sha512'])
    parser.add_argument('args', nargs='+', help='start end OR hash_value')
    
    args = parser.parse_args()
    
    if args.reverse:
        # Reverse mode: script.py -R md5 hash_value
        try_reverse_hash(args.args[0], args.hash_type)
    else:
        # Generate mode: script.py md5 1 10
        start = int(args.args[0])
        end = int(args.args[1])
        generate_hashed_b64(start, end, args.hash_type)

if __name__ == "__main__":
    main()
