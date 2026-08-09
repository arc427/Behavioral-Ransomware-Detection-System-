# SILRAD: Sysmon Dataset for Ransomware Analysis
## Overview

This dataset was created as part of the research paper:
“A Sysmon Incremental Learning System for Ransomware Analysis and Detection (SILRAD)”
by Jamil Ispahany, Md Rafiqul Islam, M. Arif Khan, and Md Zahidul Islam (Charles Sturt University, Australia, and Cyber Security Cooperative Research Centre).

The dataset contains Windows Sysmon logs generated from both benign applications (goodware) and malicious executables (ransomware). It is designed for use in machine learning–based ransomware detection, especially for incremental and online learning scenarios where concept drift plays a role.

## Archive contents

The SILRAD dataset has been zipped. The contents of the zip file can be seen below.
```
SILRAD-datase.zip
├── fasttext-all-nofamily.csv (contains all data)
├── fasttext-testmodel.csv (contains the data for testing online models)
└── fasttext-trainmodel.csv (contains the dataset for training online models)
```

## Ransomware samples featured in the Dataset

The dataset consists of nearly 200,000 Sysmon events:
- Ransomware events: 20,710
  * Harvested from 50 samples across six ransomware families:
    * [AvosLocker](https://malpedia.caad.fkie.fraunhofer.de/details/win.avos_locker)
    * [BlackBasta](https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbasta)
    * [Conti](https://malpedia.caad.fkie.fraunhofer.de/details/win.conti)
    * [Hive](https://malpedia.caad.fkie.fraunhofer.de/details/win.hive)
    * [Lockbit](https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit)
    * [REvil](https://malpedia.caad.fkie.fraunhofer.de/details/win.revil)
- Goodware events: 176,130
  * Generated from benign applications, games, and utilities (e.g., from PortableApps).


## Data Collection Methodology
- Environment:
  * Isolated Windows 11 virtual machines were deployed with Sysmon agents.
  * Sysmon logs were forwarded to a central logging server using the ELK stack (Elasticsearch, Logstash, Kibana).
- Ransomware Execution:
  * Samples executed for up to 5 minutes (until ransomware note was displayed).
  * Each VM was rolled back after execution to ensure a clean state.
- Goodware Execution:
  * Benign applications run continuously to collect background Sysmon events.
- Event Stitching:
  * Since ransomware samples lock the VM post-execution, logs were “stitched” together into a continuous stream of benign and malicious events.


# Sysmon Events
The dataset includes a variety of Sysmon event types. Some key ones observed include:
- Process creation (ID 1)
- File creation/modification (IDs 2, 11, 23)
- Network connections (ID 3, 22)
- Process termination (ID 5)
- Module/image loads (ID 7)
- Remote thread creation & process hollowing (IDs 8, 25)
- Registry modifications (IDs 12, 13)
- Named pipes (ID 17)

Note: Not all Sysmon events are malicious; legitimate applications may trigger similar events.


# Dataset Format
- Each log entry corresponds to a Sysmon event.
- Features include process/file names, registry paths, event types, and related metadata.
- Labels are provided:
  * 0 = Goodware
  * 1 = Ransomware


# Intended Use
This dataset is intended for:
- Research in machine learning–based ransomware detection
- Experiments in incremental learning and concept drift detection
- Feature selection studies (e.g., Pearson Correlation Coefficient identified top features such as TargetObject, Task, CallTrace, ParentImage)

# Performance Benchmarks (from SILRAD study)

Using this dataset, the SILRAD system achieved:
- Accuracy: 98.89%
- Precision: 94.87%
- Recall: 94.59%
- F1-Score: 94.73%
- MCC (Matthews Correlation Coefficient): 94.11%


# Citation

If you use this dataset, please cite the associated paper:

> Ispahany, J., Islam, M.R., Khan, M.A., & Islam, M.Z.
A Sysmon Incremental Learning System for Ransomware Analysis and Detection.
Charles Sturt University & Cyber Security Cooperative Research Centre.

# Acknowledgements

- Cyber Security Research Centre Limited (funded partially by the Australian Government’s Cooperative Research Centres Programme).
- VirusTotal and HybridAnalysis for ransomware samples.
- PortableApps for benign software samples.
