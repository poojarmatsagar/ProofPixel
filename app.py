import joblib
import json
import os

from flask import Flask, render_template, request, jsonify
from datetime import datetime
from chatbot import generate_chat_response
from utils.url_analyzer import url_analyzer
from database import create_database, save_url

create_database()

app = Flask(__name__)

# Statistics tracking
STATS_FILE = "statistics.json"

def load_statistics():
    """Load statistics from JSON file"""
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {
        "total_analyzed": 0,
        "safe_urls": 0,
        "phishing_urls": 0,
        "last_updated": datetime.now().isoformat()
    }

def save_statistics(stats):
    """Save statistics to JSON file"""
    stats["last_updated"] = datetime.now().isoformat()
    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
    except Exception as e:
        print(f"Error saving statistics: {e}")

def update_statistics(is_safe):
    """Update statistics after URL analysis"""
    stats = load_statistics()
    stats["total_analyzed"] += 1
    if is_safe:
        stats["safe_urls"] += 1
    else:
        stats["phishing_urls"] += 1
    save_statistics(stats)
    return stats

# Load trained model from file
MODEL_PATH = "phishing_model.pkl"
model = None

try:
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully from file")
except FileNotFoundError:
    print(f"Model file {MODEL_PATH} not found. Please train and save the model first.")
except Exception as e:
    print(f"Error loading model: {e}")


def predict_url_safety(url):
    """
    Predict if a URL is safe or phishing using comprehensive real-time analysis.
    Returns: 'safe' or 'phishing'
    """
    try:
        # Use new URL analyzer for comprehensive analysis
        analysis_result = url_analyzer.analyze_url(url)
        
        # Return simple result for backward compatibility
        return "phishing" if not analysis_result["is_safe"] else "safe"
        
    except Exception as e:
        return f"Prediction error: {str(e)}"


def analyze_url_comprehensive(url):
    """
    Perform comprehensive URL analysis with detailed results.
    Returns full analysis result with risk score and reasons.
    """
    try:
        return url_analyzer.analyze_url(url)
    except Exception as e:
        return {
            "url": url,
            "is_safe": False,
            "risk_score": 100,
            "reasons": [f"Analysis error: {str(e)}"],
            "timestamp": datetime.now().isoformat()
        }


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    features = None
    analysis = None
    
    if request.method == "POST":
        url = request.form.get("url")
        
        if url:
            try:
                # Use comprehensive analysis
                analysis = analyze_url_comprehensive(url)
                
                # Update statistics
                update_statistics(analysis["is_safe"])
                
                # For backward compatibility with template
                result = "PHISHING" if not analysis["is_safe"] else "SAFE"

                save_url(url, result)

                # Create features dict for template display
                features = {
                    "risk_score": analysis["risk_score"],
                    "reasons": analysis["reasons"],
                    "normalized_url": analysis.get("normalized_url", url)
                }
                
            except Exception as e:
                result = f"Error: {str(e)}"
    
    return render_template(
        "index.html",
        result=result,
        features=features,
        analysis=analysis
    )


@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/stats", methods=["GET"])
def get_statistics():
    """API endpoint to get current statistics"""
    try:
        stats = load_statistics()
        
        # Calculate additional metrics
        total = stats["total_analyzed"]
        safe = stats["safe_urls"]
        phishing = stats["phishing_urls"]
        
        # Calculate success rate (safe percentage)
        success_rate = (safe / total * 100) if total > 0 else 0
        
        # Calculate phishing rate
        phishing_rate = (phishing / total * 100) if total > 0 else 0
        
        return jsonify({
            **stats,
            "success_rate": round(success_rate, 2),
            "phishing_rate": round(phishing_rate, 2),
            "chart_data": {
                "pie": [safe, phishing],
                "bar": [total, safe, phishing]
            }
        })
    except Exception as e:
        return jsonify({"error": f"Failed to load statistics: {str(e)}"}), 500


@app.route("/analyze", methods=["POST"])
# def analyze():
#     """
#     API endpoint for comprehensive URL analysis
#     Returns detailed analysis with risk score and reasons
#     """
#     data = request.get_json()
#
#     if not data or "url" not in data:
#         return jsonify({"error": "URL is required"}), 400
#
#     url = data["url"]
#
#     if not url:
#         return jsonify({"error": "URL cannot be empty"}), 400
#
#     try:
#         analysis_result = analyze_url_comprehensive(url)
#
#         # Update statistics
#         update_statistics(analysis_result["is_safe"])
#
#         return jsonify(analysis_result)
#     except Exception as e:
#         return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
#

def analyze():
    """
    API endpoint for comprehensive URL analysis
    Returns detailed analysis with risk score and reasons
    """
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]

    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    try:
        analysis_result = analyze_url_comprehensive(url)

        # Update statistics
        update_statistics(analysis_result["is_safe"])

        # Determine result
        result = (
            "SAFE"
            if analysis_result["is_safe"]
            else "PHISHING"
        )

        # Save URL and prediction in database
        save_url(url, result)

        return jsonify(analysis_result)

    except Exception as e:
        return jsonify({
            "error": f"Analysis failed: {str(e)}"
        }), 500

@app.route("/chat", methods=["POST"])
def chat():

    user_message = request.form.get("message")

    if not user_message:
        return jsonify({"reply": "Please type a message."})

    reply = generate_chat_response(user_message)

    return jsonify({"reply": reply})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

