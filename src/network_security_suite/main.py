from src.network_security_suite.ml import parquet_analysis

if __name__ == "__main__":
    PATH = "/home/batman/Documents/networkguard2/src/network_security_suite/data/ml_testing.parquet"

    pq = parquet_analysis.NetworkParquetAnalysis(path=PATH)
    protocols = pq.PROTOCOLS

    for col in pq.df.columns:
        if "TCP" in col:
            print(col)
""" results = pq.comprehensive_relationship_analysis()

    pq.print_relationship_summary(results)

    high_corr = pq.find_highly_correlated_pairs(min_correlation=0.7)

    print(f"\nFound {len(high_corr)} highly correlated pairs:")
    for col1,col2,corr in high_corr[:10]:
        print(f" {col1} <-> {col2}: {corr:.3f}")

    packet_analysis = pq.analyze_packet_relationships()
    print(f"\nProtocol columns found: {sum(len(cols) for cols in packet_analysis['protocol_columns'].values())}")

"""
