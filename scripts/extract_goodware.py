import os
import pandas as pd
from pathlib import Path

# Define paths
project_dir = Path("C:/Users/hp/Behavioral-Ransomware-Detection-System-")
datasets_dir = project_dir / "data/datasets"
processed_dir = project_dir / "data/processed"

processed_dir.mkdir(parents=True, exist_ok=True)

print("Starting Goodware Extraction Process...")

# 1. MLRan Dataset Extraction
# Merge goodware description with MLRan metadata on sample_id and md5
mlran_desc_path = datasets_dir / "mlran/mlran-main/2_collected_samples_metadata/goodware_samples_description.csv"
mlran_meta_path = datasets_dir / "mlran/mlran-main/2_collected_samples_metadata/mlran_dataset_metadata.csv"
mlran_output_path = processed_dir / "mlran_goodware_extracted.csv"

if mlran_desc_path.exists() and mlran_meta_path.exists():
    print("\nProcessing MLRan goodware dataset...")
    df_desc = pd.read_csv(mlran_desc_path)
    df_meta = pd.read_csv(mlran_meta_path)
    
    # Filter metadata for goodware (sample_type == 0)
    df_meta_good = df_meta[df_meta['sample_type'] == 0]
    
    # Merge on sample_id and md5
    # Let's drop duplicate columns from df_meta before merging to avoid suffixes
    common_cols = ['sample_id', 'md5']
    meta_cols_to_keep = [col for col in df_meta_good.columns if col not in df_desc.columns or col in common_cols]
    
    df_mlran_good = pd.merge(df_desc, df_meta_good[meta_cols_to_keep], on=common_cols, how='inner')
    
    df_mlran_good.to_csv(mlran_output_path, index=False)
    print(f"Successfully extracted {len(df_mlran_good)} MLRan goodware samples to {mlran_output_path}")
else:
    print(f"Error: MLRan dataset files not found at {mlran_desc_path} or {mlran_meta_path}")

# 2. CSU Ransomware Dataset Extraction
# Filter Ransomware_Data.csv for 'Ware Type' == 'good'
csu_input_path = datasets_dir / "csu_ransomware/CSU-Ransomware-Data-main/dataset/Ransomware_Data.csv"
csu_output_path = processed_dir / "csu_goodware_extracted.csv"

if csu_input_path.exists():
    print("\nProcessing CSU goodware dataset...")
    # Read in chunks to handle memory efficiently (25MB is fine, but chunking is safer)
    chunks = []
    for chunk in pd.read_csv(csu_input_path, chunksize=50000):
        good_chunk = chunk[chunk['Ware Type'] == 'good']
        chunks.append(good_chunk)
    
    df_csu_good = pd.concat(chunks, ignore_index=True)
    df_csu_good.to_csv(csu_output_path, index=False)
    print(f"Successfully extracted {len(df_csu_good)} CSU goodware records to {csu_output_path}")
else:
    print(f"Error: CSU dataset file not found at {csu_input_path}")

# 3. RansomSet Normal Dataset Extraction
# Dataset - Normal.csv contains only benign samples. We will load and save to processed directory.
rs_input_path = datasets_dir / "ransomset/RansomSet-main/Dataset/Dataset - Normal.csv"
rs_output_path = processed_dir / "ransomset_goodware_extracted.csv"

if rs_input_path.exists():
    print("\nProcessing RansomSet normal dataset...")
    # It has system call frequencies separated by semicolons
    df_rs = pd.read_csv(rs_input_path, sep=';')
    df_rs.to_csv(rs_output_path, index=False)
    print(f"Successfully saved {len(df_rs)} RansomSet normal samples to {rs_output_path}")
else:
    print(f"Error: RansomSet dataset file not found at {rs_input_path}")

print("\nGoodware extraction process finished!")
