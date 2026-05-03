from flask import Flask, render_template, request
import pandas as pd
import joblib
import tldextract
import json
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# Load or train model
def load_or_train_model():
    try:
        return joblib.load("phishing_website_detector.pkl")
    except FileNotFoundError:
        df = pd.read_csv("phishing_smart.csv")
        X = df.drop(columns=["url", "class"])
        y = df["class"]
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        joblib.dump(model, "phishing_website_detector.pkl")
        return model

# Extract features from URL
def extract_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    tld = tldextract.extract(url).suffix
    suspicious_keywords = ['login', 'verify', 'update', 'bank', 'secure', 'account', 'webscr']

    return pd.DataFrame([{
        'LongURL': int(len(url) > 75),
        'ShortURL': int(len(url) < 20),
        'SubDomains': int(domain.count('.') > 2),
        'HTTPS': int(parsed_url.scheme == 'https'),
        'DomainRegLen': 0,
        'Favicon': 1,
        'NonStdPort': 0,
        'HTTPSDomainURL': int('https' in domain),
        'LinksInScriptTags': 0,
        'InfoEmail': int("@" in url),
        'AbnormalURL': int(domain not in url),
        'WebsiteForwarding': 0,
        'StatusBarCust': 0,
        'DisableRightClick': 0,
        'UsingPopupWindow': 0,
        'IframeRedirection': 0,
        'AgeofDomain': 0,
        'DNSRecording': 1,
        'WebsiteTraffic': 0,
        'GoogleIndex': int("google" in domain),
        'SuspiciousKeyword': int(any(k in url.lower() for k in suspicious_keywords)),
        'TLDIsSuspicious': int(tld in ['tk', 'ml', 'ga', 'cf', 'gq']),
        'BrandSpoof': int(any(b in url.lower() for b in ['paypal', 'amazon', 'bank']))
    }])

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    chart_data = [0, 0]

    if request.method == "POST":
        url = request.form["url"]
        model = load_or_train_model()
        features = extract_features(url)
        prediction = model.predict(features)[0]
        proba = model.predict_proba(features)[0]  # [phishing, legit]

        phishing_percent = round(proba[0] * 100, 2)
        legit_percent = round(proba[1] * 100, 2)
        chart_data = [phishing_percent, legit_percent]

        result = "🛑 This website is likely **PHISHING**" if prediction == 0 else "✅ This website is likely **LEGITIMATE**"

    return render_template("index.html",
                           result=result,
                           url=url,
                           chart_data=json.dumps(chart_data),
                           raw_chart_data=chart_data)
    
if __name__ == "__main__":
    app.run(debug=True)
