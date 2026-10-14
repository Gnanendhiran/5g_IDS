import os
import numpy as np
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------
# IMPORTANT
# ---------------------------------------------------------
# Replace this with the SAME raw 91-feature matrix used
# during your original Python preprocessing.
#
# Do NOT fit this on the MATLAB simulation data.
# ---------------------------------------------------------

# Example:
#
# X = df[FEATURE_NAMES].astype(float).values
#
# The following line assumes your preprocessing already
# creates X before StandardScaler.
#
# X = your_training_feature_matrix

# ---------------------------------------------------------
# Use your EXISTING preprocessing here.
# ---------------------------------------------------------

print("Exporting Python StandardScaler...")
print("")

# Example expected variables:
#
# scaler = StandardScaler()
# X_scaled = scaler.fit_transform(X)

# ---------------------------------------------------------
# Save scaler
# ---------------------------------------------------------

output_dir = "outputs/sequence_dataset"

os.makedirs(output_dir, exist_ok=True)

np.savez(
    os.path.join(output_dir, "python_scaler_91.npz"),
    mean=scaler.mean_,
    scale=scaler.scale_,
    var=scaler.var_,
    n_features_in_=scaler.n_features_in_
)

print("Scaler exported successfully.")
print("Features:", scaler.n_features_in_)
print("")

print("Mean:")
print(scaler.mean_)

print("")
print("Scale:")
print(scaler.scale_)