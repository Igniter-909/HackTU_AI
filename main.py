from HackTU.logging import logger
from HackTU.pipeline.Apt_Data_Extraction import NetworkFlowAnalyzer
from HackTU.pipeline.Apt_Data_Extraction import FlowStats
from HackTU.pipeline.Phishing_Data_Extraction import URLFeatureExtractor

import os
from dotenv import load_dotenv
import shutil
import psutil

load_dotenv()

if __name__ == "__main__":


    logger.info("Starting the application")
    analyzer = NetworkFlowAnalyzer()
    logger.info("Reached capture packets")
    analyzer.capture_packets(1000)
    logger.info("Reached export to csv")
    analyzer.export_to_csv()


    extractor = URLFeatureExtractor()
    logger.info("Reached url feature extractor")
    url = "http://www.cisco.com/c/en/us/about/legal/privacy-full.html"
    features = extractor.extract_features(url)
    logger.info("Reached print features")
    for (feature, value) in features.items():
        logger.info(f"{feature}: {value}")
    logger.info("Finished the application")

