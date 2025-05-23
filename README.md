# 🔍 Twitter-Based Cyber Threat Intelligence (CTI) Extraction

This repository provides an automated pipeline for collecting and analyzing cyber threat intelligence (CTI) from Twitter using OSINT techniques. Traditional sources like the National Vulnerability Database (NVD) often lag behind real-time developments, whereas social media platforms offer early warnings about emerging threats. Our system addresses the challenges of processing vast volumes of unstructured data by leveraging **Regular Expressions**, **Machine Learning (ML)**, and **Deep Learning (DL)** to extract and validate Indicators of Compromise (IoCs) such as **IP addresses, URLs, domains, file hashes, and CVEs**.

## 🚀 Key Contributions

- 📥 **Automatic IoC Extraction**: Harvesting threat indicators from tweets in real time.
- ✅ **IoC Validation**: Cross-verifying extracted IoCs using platforms like VirusTotal, AlienVault, MISP, MalwareBazaar, etc.
- 🤖 **Bot vs. Human Classification**: Distinguishing automated accounts using ML/DL models, interpreted with Explainable AI (XAI).
- 📊 **Reliability Assessment**: Evaluating the **accuracy, novelty, and timeliness** of IoCs derived from social media.

## 📁 Repository Structure

├── code/ # Scripts for tweet collection, preprocessing, classification, IoC extraction, bot classification

├── dataset/ # Datasets for relevant tweet classification and bot detection

├── TIP/ # Code to search IoCs in external Threat Intelligence Platforms and store results

