import json
import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

# Exact 31 features + label from main_supervised.py
categorical_features = [
    'f_same_cggt_is_hlr_oc',
    'f_same_cggt_is_hlr_ossn',
    'f_velocity_greater_than_1000',
]

numerical_features = [
    'f_count_unloop_country_last_x_hours_ul',
    'f_count_gap_ok_sai_and_all_lu',
    'f_count_ok_cl_between2lu',
    'f_count_ok_fwsm_mo_between2lu',
    'f_count_ok_fwsm_mt_between2lu',
    'f_count_ok_fwsm_report_between2lu',
    'f_count_ok_prn_between2lu',
    'f_count_ok_psi_between2lu',
    'f_count_ok_sai_between2lu',
    'f_count_ok_si_between2lu',
    'f_count_ok_sri_between2lu',
    'f_count_ok_srism_between2lu',
    'f_count_ok_ul_between2lu',
    'f_count_ok_ulgprs_between2lu',
    'f_count_ok_ussd_between2lu',
    'f_frequent_ok_cl_between2lu',
    'f_frequent_ok_fwsm_mo_between2lu',
    'f_frequent_ok_fwsm_mt_between2lu',
    'f_frequent_ok_fwsm_report_between2lu',
    'f_frequent_ok_prn_between2lu',
    'f_frequent_ok_psi_between2lu',
    'f_frequent_ok_sai_between2lu',
    'f_frequent_ok_si_between2lu',
    'f_frequent_ok_sri_between2lu',
    'f_frequent_ok_srism_between2lu',
    'f_frequent_ok_ul_between2lu',
    'f_frequent_ok_ulgprs_between2lu',
    'f_frequent_ok_ussd_between2lu',
]

used_features = categorical_features + numerical_features + ['label']


def generate_synthetic_ss7_dataset(n_samples=120, seed=42):
    rng = np.random.default_rng(seed)
    labels = rng.integers(0, 2, size=n_samples)
    data = {}

    # Normal (0) vs Attack (1) feature distributions
    # Attack traffic exhibits higher velocity anomalies, CGGT/HLR mismatch, and abnormal PSI/SRISM/UL counts
    data['f_same_cggt_is_hlr_oc'] = np.where(labels == 1, rng.binomial(1, 0.2, n_samples), rng.binomial(1, 0.85, n_samples))
    data['f_same_cggt_is_hlr_ossn'] = np.where(labels == 1, rng.binomial(1, 0.25, n_samples), rng.binomial(1, 0.85, n_samples))
    data['f_velocity_greater_than_1000'] = np.where(labels == 1, rng.binomial(1, 0.8, n_samples), rng.binomial(1, 0.05, n_samples))

    for feat in numerical_features:
        if 'count' in feat:
            if any(k in feat for k in ['psi', 'srism', 'sri', 'ul', 'unloop']):
                data[feat] = np.where(labels == 1, rng.poisson(6.0, n_samples), rng.poisson(1.0, n_samples))
            else:
                data[feat] = rng.poisson(2.0, n_samples)
        else:
            if any(k in feat for k in ['psi', 'srism', 'sri', 'ul']):
                data[feat] = np.where(labels == 1, rng.uniform(0.4, 1.0, n_samples), rng.uniform(0.0, 0.3, n_samples))
            else:
                data[feat] = rng.uniform(0.0, 0.5, n_samples)

    data['label'] = labels
    return pd.DataFrame(data)[used_features]


def evaluate(y_true, y_pred):
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "F1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
    }


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sim_dir = os.path.join(base_dir, "datasets", "Simulated_SS7")
    os.makedirs(sim_dir, exist_ok=True)

    vip_path = os.path.join(sim_dir, "post_20subs_vip_full.csv")
    normal_path = os.path.join(sim_dir, "post_20subs_normal_full.csv")

    df_vip = generate_synthetic_ss7_dataset(n_samples=120, seed=42)
    df_vip.to_csv(vip_path, index=False)

    df_normal = generate_synthetic_ss7_dataset(n_samples=200, seed=99)
    df_normal['label'] = 0
    df_normal.to_csv(normal_path, index=False)

    print(f"[+] Created synthetic dataset: {vip_path} ({df_vip.shape[0]} rows, {df_vip.shape[1]} cols)")
    print(f"[+] Created normal SSL dataset: {normal_path} ({df_normal.shape[0]} rows, {df_normal.shape[1]} cols)")

    # Replicate main_supervised.py obtain_data() split (train_size=68, test_size=17)
    train_data, test_data = train_test_split(df_vip[used_features], test_size=17, train_size=68, random_state=0)
    X_train, y_train = train_data.drop(columns=['label']), train_data['label']
    X_test, y_test = test_data.drop(columns=['label']), test_data['label']

    models = {
        "MLP_Detector": MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=42),
        "RandomForest_Detector": RandomForestClassifier(n_estimators=100, random_state=42),
    }

    results_dir = os.path.join(base_dir, "results", "Simulated_SS7", "logs")
    os.makedirs(results_dir, exist_ok=True)

    for name, clf in models.items():
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        metrics = evaluate(y_test, preds)
        out_file = os.path.join(results_dir, f"{name}_0.json")
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)
        print(f"[+] Model {name} evaluation: {json.dumps(metrics)}")


if __name__ == "__main__":
    main()
