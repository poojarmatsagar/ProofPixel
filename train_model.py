import joblib
from model import train_model

# Train the model
print("Training phishing detection model...")
model = train_model()

# Save the trained model to file
MODEL_PATH = "phishing_model.pkl"
joblib.dump(model, MODEL_PATH)

print(f"Model saved successfully to {MODEL_PATH}")
