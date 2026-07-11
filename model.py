import pandas as pd
import tldextract
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

DATASET_PATH = "urls_dataset.csv"

# ---------------------------
# FEATURE EXTRACTION
# ---------------------------
def extract_features(url):

    features = {}

    features['url_length'] = len(url)
    features['dot_count'] = url.count('.')
    features['has_hyphen'] = 1 if '-' in url else 0
    features['https'] = 1 if url.lower().startswith('https') else 0
    features['digit_count'] = sum(c.isdigit() for c in url)

    suspicious_words = ['login', 'verify', 'bank', 'update', 'free', 'secure']
    features['suspicious_word'] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    domain = tldextract.extract(url).domain
    features['domain_length'] = len(domain) if domain else 0

    features['has_at'] = 1 if '@' in url else 0

    # Small extra features to improve accuracy
    features['slash_count'] = url.count('/')
    features['question_mark'] = url.count('?')
    features['equal_count'] = url.count('=')

    return features


# ---------------------------
# LOAD DATASET
# ---------------------------
def load_dataset(path=DATASET_PATH):

    if not os.path.exists(path):
        raise FileNotFoundError("Dataset not found!")

    df = pd.read_csv(path)

    possible_labels = ['label', 'Label', 'status', 'class', 'type']
    label_col = None

    for col in possible_labels:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        raise Exception("Dataset must contain label column")

    # Normalize labels
    df[label_col] = df[label_col].astype(str).str.lower()

    df[label_col] = df[label_col].replace({
        'legitimate': 0,
        'benign': 0,
        'good': 0,
        'safe': 0,
        '0': 0,

        'phishing': 1,
        'malicious': 1,
        'bad': 1,
        'unsafe': 1,
        '1': 1
    })

    df[label_col] = pd.to_numeric(df[label_col], errors='coerce')

    df = df.dropna(subset=[label_col])

    if 'url' in df.columns:
        url_col = 'url'
    else:
        candidates = [c for c in df.columns if 'url' in c.lower()]
        url_col = candidates[0]

    return df, url_col, label_col


# ---------------------------
# TRAIN MODEL
# ---------------------------
def train_model():

    df, url_col, label_col = load_dataset()

    features = [extract_features(u) for u in df[url_col].astype(str)]

    feature_df = pd.DataFrame(features)
    feature_df['label'] = df[label_col].astype(int)

    X = feature_df.drop('label', axis=1)
    y = feature_df['label']

    # X_train, X_test, y_train, y_test = train_test_split(
    #     X, y, test_size=0.2, random_state=42
    # )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print(y.value_counts())


    # Balanced Random Forest (prevents all phishing predictions)
    model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=42
    )

    model.fit(X_train, y_train)

    return model, X_test, y_test


# ---------------------------
# STORE NEW URL INTO DATASET
# ---------------------------
def store_new_url(url, label):

    if not os.path.exists(DATASET_PATH):
        return

    df = pd.read_csv(DATASET_PATH)

    if 'url' in df.columns:
        if url.lower() in df['url'].astype(str).str.lower().values:
            return

    new_row = pd.DataFrame({
        "url": [url],
        "label": [label]
    })

    df = pd.concat([df, new_row], ignore_index=True)

    df = df.drop_duplicates(subset=['url'])

    df.to_csv(DATASET_PATH, index=False)


# ---------------------------
# PREDICTION FUNCTION
# ---------------------------
def predict_url(model, url):

    df, url_col, label_col = load_dataset()

    # If URL already exists in dataset
    if url.lower() in df[url_col].astype(str).str.lower().values:

        existing_label = int(
            df[df[url_col].str.lower() == url.lower()][label_col].values[0]
        )

        result = "PHISHING" if existing_label == 1 else "SAFE"

        # Return dictionary to avoid Jinja error
        return result, {"info": "Found in dataset"}

    # Extract features
    features = extract_features(url)
    df_features = pd.DataFrame([features])

    prediction = model.predict(df_features)[0]


    result = "PHISHING" if int(prediction) == 1 else "SAFE"

    # Save new URL to dataset
    store_new_url(url, prediction)

    return result, features
