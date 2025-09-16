import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'v2ray_tester'))

from v2ray_config_collector.core.fetcher import SourceCollector

def main():
    # 1. Fetch configurations from sources.txt
    print("Fetching configurations...")
    collector = SourceCollector(input_file="sources.txt")
    collector.fetch_all_configs()
    print("Configurations fetched.")

if __name__ == "__main__":
    main()
