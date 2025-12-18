from netguard.src.network_security_suite.ml.preprocessing.analyzers.anomaly_analyzer import AnomalyAnalyzer



if __name__=="__main__":
    PATH = "/mnt/shared/tesis/netguard/src/network_security_suite/data/packet_capture.parquet"
    an = AnomalyAnalyzer(PATH)
    print(an)
