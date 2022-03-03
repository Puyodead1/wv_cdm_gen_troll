import os
from pathlib import Path
import sys
import wv_proto2_pb2

if __name__ == "__main__":
    file = sys.argv[1]
    filepath = Path(file)
    if not filepath.is_file():
        print("File not found")
        sys.exit(1)
    client_id = wv_proto2_pb2.ClientIdentification()
    client_id.ParseFromString(
        open(filepath, "rb").read())

    print(client_id)
