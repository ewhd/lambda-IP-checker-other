import json
import gzip

def read_from_gzip(file_path):
    """
    Reads and decompresses a .gzip log file.
    Returns the decompressed contents as a string.
    """
    with gzip.open(file_path, 'rt', encoding='utf-8') as file:
        decompressed_data = file.read()
    return decompressed_data

def lambda_handler(file_path):
    """
    Reads log data, checks if IPs are known unsafe, and processes them.
    """
    all_IPs = []

    # Read data from the local gzip file
    decompressed_data = read_from_gzip(file_path)
    try:
        for line in decompressed_data.strip().split("\n"):
            log_entry = json.loads(line)
            all_IPs.append(log_entry["c-ip"])
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        raise

    print(f"Extracted IPs: {all_IPs}")
    return all_IPs

# Example usage
if __name__ == "__main__":
    log_file_path = "./data/test-data-danger-2.gz"  # Replace with your gzip file path
    lambda_handler(log_file_path)
