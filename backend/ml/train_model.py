import os
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

FEATURE_COLUMNS = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
    'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath'
]

def main():
    csv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'dataset.csv')
    
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found. Please download the dataset.")
        return

    print(f"Dataset found at {csv_path}. Loading data...")
    df = pd.read_csv(csv_path)

    # Validate columns exist
    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing_cols:
        print(f"Error: Missing columns in dataset: {missing_cols}")
        return
        
    print(f"Training on {len(df)} samples across {len(FEATURE_COLUMNS)} URL string features.")
    
    X = df[FEATURE_COLUMNS]
    y = df['CLASS_LABEL']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Logistic Regression Model on URL Features...")
    clf = LogisticRegression(max_iter=1000, random_state=42)
    clf.fit(X_train, y_train)

    print("Evaluating Model...")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
    print(f"Saving model to {model_path}")
    joblib.dump(clf, model_path)
    print("Done! The new model is ready to be used by the backend.")

if __name__ == "__main__":
    main()

# training epoch adjust 42520

# training epoch adjust 3143

# training epoch adjust 56302

# training epoch adjust 97898
