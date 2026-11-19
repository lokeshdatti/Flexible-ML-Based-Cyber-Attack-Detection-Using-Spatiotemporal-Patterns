import pandas as pd
import os

def extract_unique_labels(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    try:
        # Load the dataset
        print(f"Reading {input_file}...")
        df = pd.read_csv(input_file, low_memory=False)
        
        # Clean column names (remove leading/trailing spaces)
        df.columns = df.columns.str.strip()
        
        if 'Label' not in df.columns:
            print("Error: 'Label' column not found in the dataset.")
            return

        # Get 2 sample rows for each unique attack type
        unique_attack_rows = df.groupby('Label').head(2)
        
        # Save to CSV
        unique_attack_rows.to_csv(output_file, index=False)
        print(f"Successfully saved 2 rows per attack type to {output_file}")
        print("\nUnique Labels found:")
        print(df['Label'].unique().tolist())

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    input_path = 'cicids2017_merged_10percent.csv'
    output_path = 'unique_labels.csv'
    extract_unique_labels(input_path, output_path)
