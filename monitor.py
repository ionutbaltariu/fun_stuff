import json
import os
from hashlib import sha256
import time
import argparse
import pathlib
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger().addHandler(logging.FileHandler("D:\monitor.log"))

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Monitor a file for changes")
    arg_parser.add_argument("--file_path", help="File to monitor (or directory) as an absolute path", type=str, required=True)
    arg_parser.add_argument("--interval", help="Interval in seconds to check for changes", type=int, default=60)
    arg_parser.add_argument("--ignore", help="Ignore files with these extensions", type=str, nargs="+", default=[])
    arg_parser.add_argument("--ignore-file", help="Ignore files with given names", type=str, nargs="+" , default=[])
    arg_parser.add_argument("--ignore-folders", help="Ignore files in given folders.", type=str, nargs="+", default=[])

    args = arg_parser.parse_args()

    file_path = args.file_path
    interval = args.interval
    ignore = set(args.ignore)
    ignore_file = set(args.ignore_file)
    if interval < 1 or interval > 14400:
        logging.error("Interval must be greater than 0 and lesser (or equal) than a day! (in seconds)")
        exit(1)

    if not os.path.exists(file_path):
        logging.error(f"Given path does not exist! ({file_path})")
        exit(1)

    if os.path.isdir(file_path):
        hashes = {}

        logging.info(f"Given path is a directory! ({file_path})")

        for folder, subs, files in os.walk(file_path):
            for file in files:
                file_abs_path = os.path.join(folder, file)
                parents = pathlib.Path(file_abs_path).parents

                if any([p.name in args.ignore_folders for p in parents]):
                    continue

                if os.path.isfile(file_abs_path):
                    name, ext = os.path.splitext(file)
                    if name in ignore_file or ext in ignore:
                        continue
                    with open(file_abs_path, "rb") as f:
                        file_hash = sha256(f.read()).hexdigest()
                        if file_abs_path not in hashes:
                            hashes[file_abs_path] = file_hash

        logging.info(f"Found {len(hashes)} files in directory. Will continue with continuous monitoring.")
        logging.info("Monitoring all files in directory... Original hashes: ")
        logging.info(json.dumps(hashes, indent=4))
        while True:
            for folder, subs, files in os.walk(file_path):
                for file in files:
                    file_abs_path = os.path.join(folder, file)
                    parents = pathlib.Path(file_abs_path).parents

                    if any([p.name in args.ignore_folders for p in parents]):
                        continue
                    # logging.info(f"Checking file: {file_abs_path}")
                    if os.path.isfile(file_abs_path):
                        name, ext = os.path.splitext(file)
                        if name in ignore_file or ext in ignore:
                            continue
                        with open(file_abs_path, "rb") as f:
                            file_hash = sha256(f.read()).hexdigest()
                            if file_abs_path not in hashes:
                                logging.warning(f"New file detected: {file_abs_path}")
                                hashes[file_abs_path] = file_hash
                            else:
                                if file_hash != hashes[file_abs_path]:
                                    logging.warning(f"File change detected: {file_abs_path}")
            logging.info(f"Monitoring round finished. Sleeping for {interval}...")

            time.sleep(interval)
    else:
        logging.info(f"Monitoring single file: {file_path}")
        with open(file_path, "rb") as f:
            file_hash = sha256(f.read()).hexdigest()
            while True:
                with open(file_path, "rb") as f:
                    file_hash = sha256(f.read()).hexdigest()
                    time.sleep(interval)
                    new_file_hash = sha256(f.read()).hexdigest()
                    if file_hash != new_file_hash:
                        logging.warning(f"File change detected: {file_path}")
