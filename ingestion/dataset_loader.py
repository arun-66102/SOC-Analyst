from pathlib import Path
import sys
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ============================================================================
# Project paths
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CICIDS_DIR = (
    PROJECT_ROOT
    / "data"
    / "cicids2017"
    / "MachineLearningCVE"
)

CICIDS_LABELLED_DIR = (
    PROJECT_ROOT
    / "data"
    / "cicids2017_labelled"
)

UNSW_DIR = (
    PROJECT_ROOT
    / "data"
    / "unsw_nb15"
)

UNSW_RAW_DIR = (
    PROJECT_ROOT
    / "data"
    / "unsw_nb15_raw"
)


# ============================================================================
# Generic CSV loader
# ============================================================================

def load_csv(file_path, nrows=None):
    """
    Load a CSV dataset into a Pandas DataFrame.

    Parameters:
        file_path: Path to the CSV file.
        nrows: Optional number of rows to load.

    Returns:
        pandas.DataFrame
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {file_path}"
        )

    df = pd.read_csv(file_path, nrows=nrows)

    # CICIDS2017 contains leading/trailing spaces in column names.
    # Remove them so that columns can be accessed consistently.
    df.columns = df.columns.str.strip()

    return df


# ============================================================================
# CICIDS2017 loader (no IPs — processed MachineLearningCVE version)
# ============================================================================

def load_cicids2017_sample(
    sample_size=5000,
    random_state=42
):
    """
    Load CICIDS2017 (MachineLearningCVE — no IP columns) and return a
    development subset.

    Parameters:
        sample_size: Number of events to return.
        random_state: Seed for reproducible sampling.

    Returns:
        pandas.DataFrame containing the sampled events.
    """

    csv_files = sorted(
        CICIDS_DIR.glob("*.csv")
    )

    if not csv_files:
        raise FileNotFoundError(
            f"No CICIDS2017 CSV files found in:\n{CICIDS_DIR}"
        )

    print(f"CICIDS2017 directory:")
    print(CICIDS_DIR)

    print(f"\nFound {len(csv_files)} CSV files:\n")

    dataframes = []

    for file in csv_files:

        print(f"Reading: {file.name}")

        df = pd.read_csv(file, encoding="latin1")

        df.columns = df.columns.str.strip()

        dataframes.append(df)

    combined_df = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        f"\nTotal events available: {len(combined_df):,}"
    )

    if "Label" not in combined_df.columns:
        raise KeyError(
            "The required 'Label' column was not found "
            "after cleaning the column names."
        )

    if len(combined_df) < sample_size:

        raise ValueError(
            f"Only {len(combined_df)} events are available, "
            f"but {sample_size} were requested."
        )

    sample_df = combined_df.sample(
        n=sample_size,
        random_state=random_state
    ).reset_index(drop=True)

    return sample_df


# ============================================================================
# CICIDS2017 loader — IP-inclusive (GeneratedLabelledFlows) version
# ============================================================================

def load_cicids2017_labelled_sample(
    sample_size=5000,
    random_state=42
):
    """
    Load CICIDS2017's GeneratedLabelledFlows version, which includes real
    Source IP / Destination IP columns, and return a development subset.

    Parameters:
        sample_size: Number of events to return.
        random_state: Seed for reproducible sampling.

    Returns:
        pandas.DataFrame containing the sampled events.
    """

    csv_files = sorted(
        CICIDS_LABELLED_DIR.glob("*.csv")
    )

    if not csv_files:
        raise FileNotFoundError(
            f"No CICIDS2017 labelled CSV files found in:\n{CICIDS_LABELLED_DIR}"
        )

    print(f"CICIDS2017 (labelled, IP-inclusive) directory:")
    print(CICIDS_LABELLED_DIR)

    print(f"\nFound {len(csv_files)} CSV files:\n")

    dataframes = []

    for file in csv_files:

        print(f"Reading: {file.name}")

        # These files contain some non-UTF8 characters; latin1 reads them
        # without crashing, matching how we handled the original CICIDS2017 files.
        df = pd.read_csv(file, encoding="latin1", low_memory=False)

        df.columns = df.columns.str.strip()

        dataframes.append(df)

    combined_df = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        f"\nTotal events available: {len(combined_df):,}"
    )

    required_columns = ["Source IP", "Destination IP", "Label"]

    missing = [c for c in required_columns if c not in combined_df.columns]

    if missing:
        raise KeyError(
            f"Required column(s) not found: {missing}"
        )

    if len(combined_df) < sample_size:

        raise ValueError(
            f"Only {len(combined_df)} events are available, "
            f"but {sample_size} were requested."
        )

    sample_df = combined_df.sample(
        n=sample_size,
        random_state=random_state
    ).reset_index(drop=True)

    return sample_df


# ============================================================================
# UNSW-NB15 loader (no IPs — processed training/testing-set version)
# ============================================================================

def load_unsw_nb15_sample(
    sample_size=5000,
    random_state=42
):
    """
    Load UNSW-NB15 (training + testing sets — no IP columns) and return a
    development subset.

    Parameters:
        sample_size: Number of events to return.
        random_state: Seed for reproducible sampling.

    Returns:
        pandas.DataFrame containing the sampled events.
    """

    train_path = UNSW_DIR / "UNSW_NB15_training-set.csv"
    test_path = UNSW_DIR / "UNSW_NB15_testing-set.csv"

    print(f"UNSW-NB15 directory:")
    print(UNSW_DIR)

    print(f"\nReading: {train_path.name}")
    train_df = load_csv(train_path)

    print(f"Reading: {test_path.name}")
    test_df = load_csv(test_path)

    combined_df = pd.concat(
        [train_df, test_df],
        ignore_index=True
    )

    print(
        f"\nTotal events available: {len(combined_df):,}"
    )

    if "label" not in combined_df.columns or "attack_cat" not in combined_df.columns:
        raise KeyError(
            "The required 'label' or 'attack_cat' column was not found."
        )

    if len(combined_df) < sample_size:

        raise ValueError(
            f"Only {len(combined_df)} events are available, "
            f"but {sample_size} were requested."
        )

    sample_df = combined_df.sample(
        n=sample_size,
        random_state=random_state
    ).reset_index(drop=True)

    return sample_df


# ============================================================================
# UNSW-NB15 loader — IP-inclusive (raw) version
# ============================================================================

def load_unsw_nb15_raw_sample(
    sample_size=5000,
    random_state=42
):
    """
    Load UNSW-NB15's raw 4-part CSV release, which includes real srcip /
    dstip columns, and return a development subset.

    The raw files ship with no header row, so column names are assigned
    from NUSW-NB15_features.csv (the same data-dictionary file used
    alongside the processed version).

    Parameters:
        sample_size: Number of events to return.
        random_state: Seed for reproducible sampling.

    Returns:
        pandas.DataFrame containing the sampled events.
    """

    features_path = UNSW_DIR / "NUSW-NB15_features.csv"

    if not features_path.exists():
        raise FileNotFoundError(
            f"Features file not found: {features_path}"
        )

    features_df = pd.read_csv(features_path, encoding="latin1")
    column_names = features_df["Name"].tolist()

    csv_files = sorted(
        UNSW_RAW_DIR.glob("UNSW-NB15_*.csv")
    )

    if not csv_files:
        raise FileNotFoundError(
            f"No UNSW-NB15 raw CSV files found in:\n{UNSW_RAW_DIR}"
        )

    print(f"UNSW-NB15 (raw, IP-inclusive) directory:")
    print(UNSW_RAW_DIR)

    print(f"\nFound {len(csv_files)} CSV files:\n")

    dataframes = []

    for file in csv_files:

        print(f"Reading: {file.name}")

        # Raw files have no header row — assign names from the features file.
        df = pd.read_csv(file, header=None, low_memory=False)
        df.columns = column_names[: df.shape[1]]

        dataframes.append(df)

    combined_df = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        f"\nTotal events available: {len(combined_df):,}"
    )

    # The raw files use 'Label' (capital L), unlike the processed
    # training/testing-set files, which use lowercase 'label'.
    required_columns = ["srcip", "dstip", "Label"]

    missing = [c for c in required_columns if c not in combined_df.columns]

    if missing:
        raise KeyError(
            f"Required column(s) not found: {missing}"
        )

    if len(combined_df) < sample_size:

        raise ValueError(
            f"Only {len(combined_df)} events are available, "
            f"but {sample_size} were requested."
        )

    sample_df = combined_df.sample(
        n=sample_size,
        random_state=random_state
    ).reset_index(drop=True)

    return sample_df


# ============================================================================
# Main test
# ============================================================================

if __name__ == "__main__":

    print("Loading CICIDS2017 (labelled, IP-inclusive) development subset...\n")

    df_labelled = load_cicids2017_labelled_sample(
        sample_size=2000,
        random_state=42
    )

    print("\nDataset loaded successfully.")
    print(f"Number of events: {len(df_labelled)}")
    print(df_labelled.shape)
    print("\nSample Source IP -> Destination IP pairs:")
    print(df_labelled[["Source IP", "Destination IP", "Label"]].head())

    print("\n\nLoading UNSW-NB15 (raw, IP-inclusive) development subset...\n")

    df_raw = load_unsw_nb15_raw_sample(
        sample_size=2000,
        random_state=42
    )

    print("\nDataset loaded successfully.")
    print(f"Number of events: {len(df_raw)}")
    print(df_raw.shape)
    print("\nSample srcip -> dstip pairs:")
    print(df_raw[["srcip", "dstip", "Label"]].head())