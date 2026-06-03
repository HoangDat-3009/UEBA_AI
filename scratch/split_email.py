import os
import time

input_path = r"c:\Users\admin\Downloads\source code\UEBA\data\r4.2\email.csv"
output_dir = r"c:\Users\admin\Downloads\source code\UEBA\data\r4.2"

def split_csv(input_path, output_dir, num_splits=3):
    total_size = os.path.getsize(input_path)
    print(f"Total size: {total_size} bytes")
    
    start_time = time.time()
    
    with open(input_path, 'rb') as f:
        # Read the header
        header = f.readline()
        header_len = len(header)
        print(f"Header: {header.strip()} (length {header_len} bytes)")
        
        # Calculate target size per chunk (excluding header)
        data_size = total_size - header_len
        target_chunk_size = data_size // num_splits
        print(f"Target size per split: {target_chunk_size} bytes")
        
        chunk_idx = 1
        out_path = os.path.join(output_dir, f"email_{chunk_idx}.csv")
        out_f = open(out_path, 'wb')
        out_f.write(header)
        
        bytes_written_this_chunk = 0
        total_bytes_processed = header_len
        line_count = 0
        
        # Read line by line to keep it clean and preserve newlines correctly
        for line in f:
            out_f.write(line)
            line_len = len(line)
            bytes_written_this_chunk += line_len
            total_bytes_processed += line_len
            line_count += 1
            
            if line_count % 1000000 == 0:
                print(f"Processed {line_count} lines, {total_bytes_processed}/{total_size} bytes ({total_bytes_processed/total_size*100:.2f}%)")
                
            if bytes_written_this_chunk >= target_chunk_size and chunk_idx < num_splits:
                out_f.close()
                print(f"Finished email_{chunk_idx}.csv: {bytes_written_this_chunk} bytes")
                chunk_idx += 1
                out_path = os.path.join(output_dir, f"email_{chunk_idx}.csv")
                out_f = open(out_path, 'wb')
                out_f.write(header)
                bytes_written_this_chunk = 0
                
        out_f.close()
        print(f"Finished email_{chunk_idx}.csv: {bytes_written_this_chunk} bytes")
        print(f"Total lines processed (excluding header): {line_count}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    split_csv(input_path, output_dir)
