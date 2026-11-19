import joblib
le = joblib.load('label_encoder.pkl')
print("Classes:", le.classes_)