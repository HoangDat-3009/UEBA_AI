# File: src/ueba_pipeline.py
# ===========================================================================
# AI-Driven Enterprise UEBA — Multi-Log Correlation Pipeline
# ===========================================================================
# This module implements a full OOP pipeline that:
#   1. Ingests four heterogeneous log sources (logon, device, email, file).
#   2. Engineers behavioural features per user from each source.
#   3. Fuses all features via outer-join into a unified user profile.
#   4. Trains an Isolation Forest anomaly detector on the fused profile.
#   5. Reduces dimensionality with PCA and produces a publication-ready plot.
# ===========================================================================

import os
import logging
import warnings

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from sklearn.decomposition import PCA
import matplotlib
matplotlib.use("Agg")  # non-interactive backend for server / CI environments
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Suppress convergence / future warnings that clutter the output
warnings.filterwarnings("ignore", category=FutureWarning)


class UEBAPipeline:
    """End-to-end UEBA pipeline with multi-log correlation and anomaly detection.

    Parameters
    ----------
    data_dir : str
        Path to the directory containing the four CSV log files.
    contamination : float, default 0.05
        Expected proportion of anomalies in the dataset.  Passed directly to
        ``sklearn.ensemble.IsolationForest``.
    """

    def __init__(self, data_dir: str, contamination: float = 0.05) -> None:
        self.data_dir = data_dir
        self.contamination = contamination

        # Model components — initialised here so they can be reused / inspected
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = MinMaxScaler()
        self.pca = PCA(n_components=2, random_state=42)

        logger.info(
            "UEBAPipeline initialised  |  data_dir=%s  |  contamination=%.4f",
            self.data_dir,
            self.contamination,
        )

    # -----------------------------------------------------------------------
    # Feature-engineering helpers (one per log source)
    # -----------------------------------------------------------------------

    def process_logon(self) -> pd.DataFrame:
        """Ingest ``logon.csv`` and compute per-user login behavioural features.

        Features
        --------
        total_logins : int
            Total number of login events for the user.
        off_hour_logins : int
            Number of logins that occurred outside normal working hours
            (before 07:00 or after 18:00).

        Returns
        -------
        pd.DataFrame
            Indexed by *user* with the two feature columns.
        """
        filepath = os.path.join(self.data_dir, "logon.csv")
        try:
            df = pd.read_csv(filepath)
            logger.info("Loaded logon.csv  |  %d records", len(df))
        except FileNotFoundError:
            logger.warning("logon.csv not found — skipping logon features.")
            return pd.DataFrame(columns=["user", "total_logins", "off_hour_logins"])

        # Normalise column names to lowercase for resilience
        df.columns = df.columns.str.strip().str.lower()

        # Detect the datetime column (common names: date, datetime, timestamp)
        date_col = None
        for candidate in ("date", "datetime", "timestamp", "time", "logon_date"):
            if candidate in df.columns:
                date_col = candidate
                break

        if date_col is not None:
            df[date_col] = pd.to_datetime(df[date_col], errors="coerce")
            df["hour"] = df[date_col].dt.hour
        else:
            # If no recognisable date column, set hour to NaN → off_hour = 0
            logger.warning("No datetime column found in logon.csv — off-hour "
                           "analysis will be unavailable.")
            df["hour"] = np.nan

        # Compute features grouped by user
        total_logins = df.groupby("user").size().reset_index(name="total_logins")

        off_mask = (df["hour"] < 7) | (df["hour"] > 18)
        off_hour_logins = (
            df[off_mask]
            .groupby("user")
            .size()
            .reset_index(name="off_hour_logins")
        )

        result = total_logins.merge(off_hour_logins, on="user", how="left").fillna(0)
        result["off_hour_logins"] = result["off_hour_logins"].astype(int)

        logger.info("Logon features computed  |  %d unique users", len(result))
        return result

    # -----------------------------------------------------------------------

    def process_device(self) -> pd.DataFrame:
        """Ingest ``device.csv`` and compute per-user USB behavioural features.

        Features
        --------
        total_usb_connects : int
            Total USB connection/disconnection events.
        off_hour_usb : int
            USB events outside normal working hours (before 07:00 or after 18:00).

        Returns
        -------
        pd.DataFrame
        """
        filepath = os.path.join(self.data_dir, "device.csv")
        try:
            df = pd.read_csv(filepath)
            logger.info("Loaded device.csv  |  %d records", len(df))
        except FileNotFoundError:
            logger.warning("device.csv not found — skipping device features.")
            return pd.DataFrame(columns=["user", "total_usb_connects", "off_hour_usb"])

        df.columns = df.columns.str.strip().str.lower()

        # Detect datetime column
        date_col = None
        for candidate in ("date", "datetime", "timestamp", "time", "connect_date"):
            if candidate in df.columns:
                date_col = candidate
                break

        if date_col is not None:
            df[date_col] = pd.to_datetime(df[date_col], errors="coerce")
            df["hour"] = df[date_col].dt.hour
        else:
            logger.warning("No datetime column found in device.csv.")
            df["hour"] = np.nan

        total_connects = (
            df.groupby("user").size().reset_index(name="total_usb_connects")
        )

        off_mask = (df["hour"] < 7) | (df["hour"] > 18)
        off_hour_usb = (
            df[off_mask]
            .groupby("user")
            .size()
            .reset_index(name="off_hour_usb")
        )

        result = total_connects.merge(off_hour_usb, on="user", how="left").fillna(0)
        result["off_hour_usb"] = result["off_hour_usb"].astype(int)

        logger.info("Device features computed  |  %d unique users", len(result))
        return result

    # -----------------------------------------------------------------------

    def process_email(self) -> pd.DataFrame:
        """Ingest ``email.csv`` and compute per-user e-mail behavioural features.

        Features
        --------
        total_emails : int
            Total e-mail events for the user.
        external_emails : int
            If an ``external`` or ``to`` column exists, counts external-domain
            messages.  Falls back to counting emails with attachments if the
            column is unavailable.

        Returns
        -------
        pd.DataFrame
        """
        filepath = os.path.join(self.data_dir, "email.csv")
        try:
            df = pd.read_csv(filepath)
            logger.info("Loaded email.csv  |  %d records", len(df))
        except FileNotFoundError:
            logger.warning("email.csv not found — skipping email features.")
            return pd.DataFrame(columns=["user", "total_emails", "external_emails"])

        df.columns = df.columns.str.strip().str.lower()

        total_emails = df.groupby("user").size().reset_index(name="total_emails")

        # Strategy 1: explicit 'external' boolean / flag column
        if "external" in df.columns:
            external = (
                df[df["external"].astype(str).str.strip().str.lower().isin(
                    ["1", "true", "yes", "external"]
                )]
                .groupby("user")
                .size()
                .reset_index(name="external_emails")
            )
        # Strategy 2: detect external by inspecting the 'to' field for
        #             domains that differ from the organisation's domain
        elif "to" in df.columns:
            # Heuristic: the most common domain is the internal domain
            all_domains = (
                df["to"]
                .astype(str)
                .str.extract(r"@([\w.-]+)", expand=False)
                .dropna()
            )
            if not all_domains.empty:
                internal_domain = all_domains.mode().iloc[0]
                df["_is_external"] = ~df["to"].astype(str).str.contains(
                    internal_domain, case=False, na=False
                )
            else:
                df["_is_external"] = False

            external = (
                df[df["_is_external"]]
                .groupby("user")
                .size()
                .reset_index(name="external_emails")
            )
        # Strategy 3: count emails with attachments as a proxy for risk
        elif "attachments" in df.columns:
            has_attachment = df["attachments"].astype(str).str.strip() != ""
            has_attachment &= df["attachments"].astype(str).str.lower() != "nan"
            has_attachment &= df["attachments"].astype(str) != "0"
            external = (
                df[has_attachment]
                .groupby("user")
                .size()
                .reset_index(name="external_emails")
            )
        else:
            logger.warning(
                "No 'external', 'to', or 'attachments' column in email.csv "
                "— external_emails set to 0."
            )
            external = pd.DataFrame(columns=["user", "external_emails"])

        result = total_emails.merge(external, on="user", how="left").fillna(0)
        result["external_emails"] = result["external_emails"].astype(int)

        logger.info("Email features computed  |  %d unique users", len(result))
        return result

    # -----------------------------------------------------------------------

    def process_file(self) -> pd.DataFrame:
        """Ingest ``file.csv`` and compute per-user file-access behavioural features.

        Features
        --------
        total_file_access : int
            Total file access events.
        exe_zip_downloads : int
            Events involving ``.exe`` or ``.zip`` files (potential exfiltration).

        Returns
        -------
        pd.DataFrame
        """
        filepath = os.path.join(self.data_dir, "file.csv")
        try:
            df = pd.read_csv(filepath)
            logger.info("Loaded file.csv  |  %d records", len(df))
        except FileNotFoundError:
            logger.warning("file.csv not found — skipping file features.")
            return pd.DataFrame(columns=["user", "total_file_access", "exe_zip_downloads"])

        df.columns = df.columns.str.strip().str.lower()

        total_access = (
            df.groupby("user").size().reset_index(name="total_file_access")
        )

        # Look for a column that holds the filename / path
        file_col = None
        for candidate in ("filename", "file", "filepath", "file_path", "content",
                          "file_name", "name", "url"):
            if candidate in df.columns:
                file_col = candidate
                break

        if file_col is not None:
            exe_zip_mask = df[file_col].astype(str).str.lower().str.contains(
                r"\.(?:exe|zip)", regex=True, na=False
            )
            exe_zip = (
                df[exe_zip_mask]
                .groupby("user")
                .size()
                .reset_index(name="exe_zip_downloads")
            )
        else:
            # Fallback: search ALL string columns for .exe / .zip patterns
            logger.warning("No explicit filename column — scanning all text columns.")
            str_cols = df.select_dtypes(include="object").columns.tolist()
            combined_text = df[str_cols].astype(str).agg(" ".join, axis=1)
            exe_zip_mask = combined_text.str.lower().str.contains(
                r"\.(?:exe|zip)", regex=True, na=False
            )
            exe_zip = (
                df[exe_zip_mask]
                .groupby("user")
                .size()
                .reset_index(name="exe_zip_downloads")
            )

        result = total_access.merge(exe_zip, on="user", how="left").fillna(0)
        result["exe_zip_downloads"] = result["exe_zip_downloads"].astype(int)

        logger.info("File features computed  |  %d unique users", len(result))
        return result

    def process_http(self) -> pd.DataFrame:
        """Ingest ``http.csv`` and compute per-user web browsing features."""
        filepath = os.path.join(self.data_dir, "http.csv")
        try:
            df = pd.read_csv(filepath)
            logger.info("Loaded http.csv  |  %d records", len(df))
        except FileNotFoundError:
            logger.warning("http.csv not found — skipping HTTP features.")
            return pd.DataFrame(columns=["user", "total_http_requests", "off_hour_http"])

        df.columns = df.columns.str.strip().str.lower()

        date_col = None
        for candidate in ("date", "datetime", "timestamp", "time"):
            if candidate in df.columns:
                date_col = candidate
                break

        if date_col is not None:
            df[date_col] = pd.to_datetime(df[date_col], errors="coerce")
            df["hour"] = df[date_col].dt.hour
        else:
            logger.warning("No datetime column found in http.csv.")
            df["hour"] = np.nan

        total_http = df.groupby("user").size().reset_index(name="total_http_requests")

        off_mask = (df["hour"] < 7) | (df["hour"] > 18)
        off_hour_http = (
            df[off_mask]
            .groupby("user")
            .size()
            .reset_index(name="off_hour_http")
        )

        result = total_http.merge(off_hour_http, on="user", how="left").fillna(0)
        result["off_hour_http"] = result["off_hour_http"].astype(int)

        logger.info("HTTP features computed  |  %d unique users", len(result))
        return result

    # -----------------------------------------------------------------------

    def process_psychometric(self) -> pd.DataFrame:
        """Ingest ``psychometric.csv`` and extract personality scores."""
        filepath = os.path.join(self.data_dir, "psychometric.csv")
        try:
            df = pd.read_csv(filepath)
            logger.info("Loaded psychometric.csv  |  %d records", len(df))
        except FileNotFoundError:
            logger.warning("psychometric.csv not found — skipping psychometric features.")
            return pd.DataFrame(columns=["user", "o_score", "c_score", "e_score", "a_score", "n_score"])
        
        df.columns = df.columns.str.strip().str.lower()
        if "user_id" in df.columns:
            df = df.rename(columns={"user_id": "user"})
        
        cols_to_keep = ["user"]
        for trait in ["o", "c", "e", "a", "n"]:
            if trait in df.columns:
                df = df.rename(columns={trait: f"{trait}_score"})
                cols_to_keep.append(f"{trait}_score")
        
        result = df[cols_to_keep].copy()
        result = result.groupby("user").mean().reset_index()
        logger.info("Psychometric features computed  |  %d unique users", len(result))
        return result

    # -----------------------------------------------------------------------

    def process_ldap(self) -> pd.DataFrame:
        """Ingest LDAP csv files and track role changes over time."""
        import glob
        ldap_dir = os.path.join(self.data_dir, "LDAP")
        csv_files = glob.glob(os.path.join(ldap_dir, "*.csv"))
        if not csv_files:
            logger.warning("No LDAP csv files found — skipping LDAP features.")
            return pd.DataFrame(columns=["user", "role_changes"])

        all_ldap = []
        for file in csv_files:
            try:
                df = pd.read_csv(file)
                df.columns = df.columns.str.strip().str.lower()
                if "user_id" in df.columns and "role" in df.columns:
                    df = df.rename(columns={"user_id": "user"})
                    df["month"] = os.path.basename(file).replace(".csv", "")
                    all_ldap.append(df[["user", "role", "month"]])
            except Exception as e:
                logger.error(f"Error reading {file}: {e}")

        if not all_ldap:
            return pd.DataFrame(columns=["user", "role_changes"])

        combined = pd.concat(all_ldap)
        role_changes = combined.groupby('user')['role'].nunique().reset_index(name='role_changes')
        role_changes["role_changes"] = (role_changes["role_changes"] - 1).clip(lower=0)

        logger.info("LDAP features computed  |  %d unique users", len(role_changes))
        return role_changes

    # -----------------------------------------------------------------------
    # Core pipeline stages
    # -----------------------------------------------------------------------

    def build_master_profile(self) -> pd.DataFrame:
        """Merge all per-source feature DataFrames into a single master profile.

        The merge strategy is an **outer join** on the ``user`` column so that
        users appearing in only a subset of logs are still represented (with
        missing features filled as 0).

        Returns
        -------
        pd.DataFrame
            One row per user, with all behavioural features consolidated.
        """
        logger.info("=" * 70)
        logger.info("STAGE 1 — Multi-Log Feature Engineering & Correlation")
        logger.info("=" * 70)

        df_logon = self.process_logon()
        df_device = self.process_device()
        df_email = self.process_email()
        df_file = self.process_file()
        df_http = self.process_http()
        df_psy = self.process_psychometric()
        df_ldap = self.process_ldap()

        # Sequential outer joins
        master = df_logon
        for right_df in [df_device, df_email, df_file, df_http, df_psy, df_ldap]:
            if right_df.empty:
                continue
            master = master.merge(right_df, on="user", how="outer")

        master = master.fillna(0)

        # Convert all feature columns to numeric (safety net)
        feature_cols = [c for c in master.columns if c != "user"]
        for col in feature_cols:
            master[col] = pd.to_numeric(master[col], errors="coerce").fillna(0)

        logger.info("-" * 70)
        logger.info(
            "Master profile built  |  %d users  |  %d features",
            len(master),
            len(feature_cols),
        )
        logger.info("Features: %s", feature_cols)
        logger.info("-" * 70)

        return master

    # -----------------------------------------------------------------------

    def train_predict(self, df_master: pd.DataFrame):
        """Scale features, fit the Isolation Forest, and generate predictions.

        Parameters
        ----------
        df_master : pd.DataFrame
            The master user-profile DataFrame produced by ``build_master_profile``.

        Returns
        -------
        df_master : pd.DataFrame
            Original DataFrame augmented with ``anomaly_label`` and
            ``anomaly_score`` columns.
        scaled_features : np.ndarray
            The MinMax-scaled feature matrix (used downstream for PCA).
        """
        logger.info("=" * 70)
        logger.info("STAGE 2 — Anomaly Detection (Isolation Forest)")
        logger.info("=" * 70)

        # Separate identifier from features
        users = df_master["user"].copy()
        feature_cols = [c for c in df_master.columns if c != "user"]
        X = df_master[feature_cols].values.astype(np.float64)

        # Scale to [0, 1]
        scaled_features = self.scaler.fit_transform(X)
        logger.info("Feature matrix scaled  |  shape=%s", scaled_features.shape)

        # Fit & predict
        self.model.fit(scaled_features)
        labels = self.model.predict(scaled_features)       # +1 normal, -1 anomaly
        scores = self.model.decision_function(scaled_features)  # lower → more anomalous

        df_master = df_master.copy()
        df_master["anomaly_label"] = labels
        df_master["anomaly_score"] = scores

        n_anomalies = int((labels == -1).sum())
        n_normal = int((labels == 1).sum())
        logger.info(
            "Detection complete  |  Normal=%d  |  Anomalous=%d  |  Ratio=%.2f%%",
            n_normal,
            n_anomalies,
            100 * n_anomalies / max(len(labels), 1),
        )

        return df_master, scaled_features

    # -----------------------------------------------------------------------

    def visualize_pca(
        self,
        df_master: pd.DataFrame,
        scaled_features: np.ndarray,
    ) -> None:
        """Reduce dimensionality with PCA and render a publication-quality scatter.

        Parameters
        ----------
        df_master : pd.DataFrame
            Must contain ``anomaly_label`` column.
        scaled_features : np.ndarray
            MinMax-scaled feature matrix.
        """
        logger.info("=" * 70)
        logger.info("STAGE 3 — Dimensionality Reduction & Visualisation (PCA)")
        logger.info("=" * 70)

        pca_result = self.pca.fit_transform(scaled_features)
        df_master = df_master.copy()
        df_master["PC1"] = pca_result[:, 0]
        df_master["PC2"] = pca_result[:, 1]

        explained = self.pca.explained_variance_ratio_
        logger.info(
            "PCA variance explained  |  PC1=%.2f%%  |  PC2=%.2f%%  |  Total=%.2f%%",
            explained[0] * 100,
            explained[1] * 100,
            explained.sum() * 100,
        )

        # ----- Matplotlib / Seaborn scatter plot -----
        palette = {1: "#2ecc71", -1: "#e74c3c"}
        label_map = {1: "Normal", -1: "Anomalous (Insider Threat)"}
        df_master["label_text"] = df_master["anomaly_label"].map(label_map)

        fig, ax = plt.subplots(figsize=(14, 9))

        # Background styling
        fig.patch.set_facecolor("#0d1117")
        ax.set_facecolor("#161b22")

        # Draw each class separately so the legend is readable
        for label_val, colour in palette.items():
            subset = df_master[df_master["anomaly_label"] == label_val]
            ax.scatter(
                subset["PC1"],
                subset["PC2"],
                c=colour,
                label=label_map[label_val],
                alpha=0.75 if label_val == 1 else 0.95,
                s=30 if label_val == 1 else 120,
                edgecolors="white" if label_val == -1 else "none",
                linewidths=0.8 if label_val == -1 else 0,
                zorder=2 if label_val == 1 else 3,
            )

        # Annotate anomalous users
        anomalies = df_master[df_master["anomaly_label"] == -1]
        for _, row in anomalies.iterrows():
            ax.annotate(
                row["user"],
                (row["PC1"], row["PC2"]),
                textcoords="offset points",
                xytext=(8, 6),
                fontsize=7,
                color="#f8f8f2",
                fontweight="bold",
                alpha=0.85,
            )

        # Titles & labels
        ax.set_title(
            "UEBA Multi-log Anomaly Detection (PCA Reduced)",
            fontsize=18,
            fontweight="bold",
            color="#f0f6fc",
            pad=20,
        )
        ax.set_xlabel(
            f"PC1 ({explained[0] * 100:.1f}% variance)",
            fontsize=13,
            color="#8b949e",
        )
        ax.set_ylabel(
            f"PC2 ({explained[1] * 100:.1f}% variance)",
            fontsize=13,
            color="#8b949e",
        )

        # Grid & spines
        ax.grid(True, linestyle="--", linewidth=0.4, alpha=0.3, color="#30363d")
        for spine in ax.spines.values():
            spine.set_color("#30363d")
        ax.tick_params(colors="#8b949e")

        # Legend
        legend = ax.legend(
            loc="upper right",
            fontsize=11,
            frameon=True,
            facecolor="#21262d",
            edgecolor="#30363d",
            labelcolor="#f0f6fc",
        )
        legend.get_frame().set_alpha(0.9)

        plt.tight_layout()
        output_path = os.path.join(self.data_dir, "..", "ueba_pca_result.png")
        output_path = os.path.normpath(output_path)
        fig.savefig(output_path, dpi=200, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close(fig)
        logger.info("PCA plot saved → %s", output_path)

    # -----------------------------------------------------------------------
    # Convenience runner
    # -----------------------------------------------------------------------

    def run(self) -> pd.DataFrame:
        """Execute the full pipeline end-to-end and return the scored master profile."""
        df_master = self.build_master_profile()

        if df_master.empty or len(df_master) < 2:
            logger.error(
                "Insufficient data to train a model (need ≥ 2 users). "
                "Please check your CSV files in '%s'.",
                self.data_dir,
            )
            return df_master

        df_master, scaled_features = self.train_predict(df_master)
        self.visualize_pca(df_master, scaled_features)
        return df_master

    # -----------------------------------------------------------------------
    # Web-oriented runner (returns JSON-serialisable dict)
    # -----------------------------------------------------------------------

    def run_for_web(self) -> dict:
        """Execute the pipeline and return results as a JSON-friendly dictionary.

        This method is used by the Flask web server to feed the dashboard.
        It returns all data needed for: summary cards, PCA scatter, radar
        chart, bar chart, heatmap, and the threats table.

        Returns
        -------
        dict
            Keys: ``users``, ``anomalies``, ``pca``, ``correlation``,
            ``feature_names``, ``summary``, ``feature_averages``.
        """
        df_master = self.build_master_profile()

        if df_master.empty or len(df_master) < 2:
            logger.error(
                "Insufficient data to train a model (need ≥ 2 users). "
                "Please check your CSV files in '%s'.",
                self.data_dir,
            )
            return {"error": "Insufficient data", "users": [], "anomalies": [],
                    "pca": [], "correlation": [], "feature_names": [],
                    "summary": {}, "feature_averages": {}}

        df_master, scaled_features = self.train_predict(df_master)

        # --- PCA for visualisation ---
        pca_result = self.pca.fit_transform(scaled_features)
        df_master = df_master.copy()
        df_master["PC1"] = pca_result[:, 0]
        df_master["PC2"] = pca_result[:, 1]

        explained = self.pca.explained_variance_ratio_

        # --- Feature metadata ---
        feature_cols = [
            c for c in df_master.columns
            if c not in ("user", "anomaly_label", "anomaly_score", "PC1", "PC2", "label_text")
        ]

        # --- Correlation matrix (for heatmap) ---
        corr_matrix = df_master[feature_cols].corr().round(3)
        correlation_data = {
            "labels": feature_cols,
            "values": corr_matrix.values.tolist(),
        }

        # --- Feature averages (for radar chart baseline) ---
        feature_averages = df_master[feature_cols].mean().round(2).to_dict()

        # --- All users data (for PCA scatter + table) ---
        users_data = []
        for _, row in df_master.iterrows():
            user_entry = {
                "user": row["user"],
                "anomaly_label": int(row["anomaly_label"]),
                "anomaly_score": round(float(row["anomaly_score"]), 4),
                "pc1": round(float(row["PC1"]), 4),
                "pc2": round(float(row["PC2"]), 4),
            }
            for fc in feature_cols:
                user_entry[fc] = int(row[fc])
            users_data.append(user_entry)

        # --- Anomalies only (sorted by score ascending = most dangerous first) ---
        anomalies_df = df_master[df_master["anomaly_label"] == -1].copy()
        anomalies_df = anomalies_df.sort_values("anomaly_score", ascending=True)

        anomalies_data = []
        for rank, (_, row) in enumerate(anomalies_df.iterrows(), start=1):
            entry = {
                "rank": rank,
                "user": row["user"],
                "anomaly_score": round(float(row["anomaly_score"]), 4),
            }
            for fc in feature_cols:
                entry[fc] = int(row[fc])
            anomalies_data.append(entry)

        # --- Summary statistics ---
        n_total = len(df_master)
        n_anomalies = len(anomalies_df)
        summary = {
            "total_users": n_total,
            "anomalous_users": n_anomalies,
            "normal_users": n_total - n_anomalies,
            "anomaly_rate": round(100 * n_anomalies / max(n_total, 1), 2),
            "num_features": len(feature_cols),
            "num_log_sources": 4,
            "pca_variance_pc1": round(float(explained[0] * 100), 1),
            "pca_variance_pc2": round(float(explained[1] * 100), 1),
        }

        logger.info("Web data prepared  |  %d users  |  %d anomalies", n_total, n_anomalies)

        return {
            "users": users_data,
            "anomalies": anomalies_data,
            "pca": {"pc1_var": summary["pca_variance_pc1"],
                    "pc2_var": summary["pca_variance_pc2"]},
            "correlation": correlation_data,
            "feature_names": feature_cols,
            "summary": summary,
            "feature_averages": feature_averages,
        }

    # -----------------------------------------------------------------------
    # Export Models
    # -----------------------------------------------------------------------

    def export_model(self, model_path: str, scaler_path: str):
        """Export the trained Isolation Forest and MinMaxScaler to disk."""
        import joblib
        # Ensure directories exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        logger.info("Exported model to %s and scaler to %s", model_path, scaler_path)



# ===========================================================================
# MAIN EXECUTION
# ===========================================================================

if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Run the pipeline
    # ------------------------------------------------------------------
    # Resolve data_dir relative to this script's location so it works
    # regardless of the caller's working directory.
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _data_dir = os.path.join(_script_dir, "..", "data", "r4.2")
    _data_dir = os.path.normpath(_data_dir)

    pipeline = UEBAPipeline(data_dir=_data_dir, contamination=0.05)
    df_result = pipeline.run()

    if df_result.empty:
        logger.error("Pipeline produced no results. Exiting.")
        raise SystemExit(1)

    # ------------------------------------------------------------------
    # Report: Top-10 Most Dangerous Users (Insider Threat Candidates)
    # ------------------------------------------------------------------
    anomalies = df_result[df_result["anomaly_label"] == -1].copy()
    anomalies = anomalies.sort_values("anomaly_score", ascending=True)

    top_n = min(10, len(anomalies))

    print("\n")
    print("=" * 90)
    print("  [!] TOP {} INSIDER THREAT CANDIDATES -- Multi-Log Correlation Report".format(top_n))
    print("=" * 90)

    if top_n == 0:
        print("  [OK] No anomalies detected with the current contamination threshold.")
    else:
        # Identify feature columns for the summary table
        feature_cols = [
            c for c in df_result.columns
            if c not in ("user", "anomaly_label", "anomaly_score", "PC1", "PC2", "label_text")
        ]

        header = (
            f"{'Rank':<5} {'User':<18} {'Score':>8} | "
            + "  ".join(f"{col[:16]:>16}" for col in feature_cols)
        )
        print(header)
        print("-" * len(header))

        for rank, (_, row) in enumerate(anomalies.head(top_n).iterrows(), start=1):
            feature_vals = "  ".join(
                f"{int(row[col]):>16}" for col in feature_cols
            )
            print(
                f"{rank:<5} {row['user']:<18} {row['anomaly_score']:>8.4f} | {feature_vals}"
            )

        print("-" * len(header))
        print(
            f"\n  [STATS] Total users analysed : {len(df_result)}"
            f"\n  [ALERT] Anomalies detected   : {len(anomalies)}"
            f"\n  [SAFE]  Normal users         : {len(df_result) - len(anomalies)}"
            f"\n  [DATA]  Features correlated  : {len(feature_cols)} "
            f"(from {sum(1 for _ in ['logon','device','email','file'])} log sources)"
        )

    print("=" * 90)
    print("  [FILE] Full results saved -> df_result DataFrame")
    print("  [IMG]  PCA visualisation -> ueba_pca_result.png")
    print("=" * 90)
    print()

