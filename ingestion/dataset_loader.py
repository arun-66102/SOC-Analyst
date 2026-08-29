from pathlib import Path
import pandas as pd

import sys

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

UNSW_DIR = (
    PROJECT_ROOT
    / "data"
    / "unsw_nb15"
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
# CICIDS2017 loader
# ============================================================================

def load_cicids2017_sample(
    sample_size=5000,
    random_state=42
):
    """
    Load CICIDS2017 and return a development subset.

    Parameters:
        sample_size: Number of events to return.
        random_state: Seed for reproducible sampling.

    Returns:
        pandas.DataFrame containing the sampled events.
    """

    # Find all CICIDS2017 CSV files.
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

    # ------------------------------------------------------------------------
    # Read every CICIDS2017 CSV
    # ------------------------------------------------------------------------

    for file in csv_files:

        print(f"Reading: {file.name}")

        df = pd.read_csv(file)

        # Remove leading/trailing whitespace from column names.
        df.columns = df.columns.str.strip()

        dataframes.append(df)

    # ------------------------------------------------------------------------
    # Combine all files
    # ------------------------------------------------------------------------

    combined_df = pd.concat(
        dataframes,
        ignore_index=True
    )

    print(
        f"\nTotal events available: {len(combined_df):,}"
    )

    # ------------------------------------------------------------------------
    # Verify required label column
    # ------------------------------------------------------------------------

    if "Label" not in combined_df.columns:
        raise KeyError(
            "The required 'Label' column was not found "
            "after cleaning the column names."
        )

    # ------------------------------------------------------------------------
    # Check whether enough events exist
    # ------------------------------------------------------------------------

    if len(combined_df) < sample_size:

        raise ValueError(
            f"Only {len(combined_df)} events are available, "
            f"but {sample_size} were requested."
        )

    # ------------------------------------------------------------------------
    # Create reproducible development sample
    # ------------------------------------------------------------------------

    sample_df = combined_df.sample(
        n=sample_size,
        random_state=random_state
    ).reset_index(drop=True)

    return sample_df


# ============================================================================
# UNSW-NB15 loader
# ============================================================================

def load_unsw_nb15_sample(
    sample_size=5000,
    random_state=42
):
    """
    Load UNSW-NB15 (training + testing sets) and return a development subset.

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

    # ------------------------------------------------------------------------
    # Read training and testing files
    # ------------------------------------------------------------------------

    print(f"\nReading: {train_path.name}")
    train_df = load_csv(train_path)

    print(f"Reading: {test_path.name}")
    test_df = load_csv(test_path)

    # ------------------------------------------------------------------------
    # Combine both files
    # ------------------------------------------------------------------------

    combined_df = pd.concat(
        [train_df, test_df],
        ignore_index=True
    )

    print(
        f"\nTotal events available: {len(combined_df):,}"
    )

    # ------------------------------------------------------------------------
    # Verify required label columns
    # ------------------------------------------------------------------------

    if "label" not in combined_df.columns or "attack_cat" not in combined_df.columns:
        raise KeyError(
            "The required 'label' or 'attack_cat' column was not found."
        )

    # ------------------------------------------------------------------------
    # Check whether enough events exist
    # ------------------------------------------------------------------------

    if len(combined_df) < sample_size:

        raise ValueError(
            f"Only {len(combined_df)} events are available, "
            f"but {sample_size} were requested."
        )

    # ------------------------------------------------------------------------
    # Create reproducible development sample
    # ------------------------------------------------------------------------

    sample_df = combined_df.sample(
        n=sample_size,
        random_state=random_state
    ).reset_index(drop=True)

    return sample_df


# ============================================================================
# Main test
# ============================================================================

if __name__ == "__main__":

    print(
        "Loading CICIDS2017 development subset...\n"
    )

    df = load_cicids2017_sample(
        sample_size=5000,
        random_state=42
    )

    print("\nDataset loaded successfully.")

    print(
        f"Number of events: {len(df)}"
    )

    print(
        f"\nDataset shape:"
    )

    print(df.shape)

    print(
        "\nNumber of columns:"
    )

    print(len(df.columns))

    print(
        "\nFirst 10 columns:"
    )

    print(df.columns[:10].tolist())

    print(
        "\nLabel distribution:"
    )

    print(
        df["Label"].value_counts()
    )

    print(
        "\n\nLoading UNSW-NB15 development subset...\n"
    )

    unsw_df = load_unsw_nb15_sample(
        sample_size=5000,
        random_state=42
    )
    
    print("\nDataset loaded successfully.")

    print(
        f"Number of events: {len(unsw_df)}"
    )

    print(unsw_df.shape)

    print(
        "\nLabel distribution:"
    )

    print(
        unsw_df["label"].value_counts()
    )

    print(
        "\nAttack category distribution:"
    )

    print(
        unsw_df["attack_cat"].value_counts()
    )