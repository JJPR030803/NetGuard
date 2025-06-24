
import polars as pl

if __name__ == "__main__":
    df = pl.read_parquet("/home/batman/Documents/networkguard2/logs/performance_metrics.parquet")
    dict = df.to_dicts()
    print(dict)
