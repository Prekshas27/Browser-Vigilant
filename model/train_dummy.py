import pickle
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Create dummy train data: 100 samples, 30 features
X_train = np.random.rand(100, 30) * 10 
# Labels: 0 for normal, 1 for malicious
y_train = np.random.randint(2, size=100)

rf = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
rf.fit(X_train, y_train)

with open("random_forest.pkl", "wb") as f:
    pickle.dump(rf, f)

print("Created a dummy random_forest.pkl with 30 features.")
