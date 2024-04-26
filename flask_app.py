from flask import Flask, request, jsonify, render_template, redirect
import pickle
import numpy as np
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)
classifier_model = pickle.load(open('classifier.pkl', 'rb'))
labels_encoder = pickle.load(open('labels_encoder.pkl', 'rb'))


def check_request_malicious(headers):
    # Convert headers to a list
    headers_list = list(headers.values())

    # Label encode the headers
    label_encoder = LabelEncoder()
    headers_encoded = label_encoder.fit_transform(headers_list)

    # Apply any other feature extraction/preprocessing steps here
    # ...

    # Pad the encoded headers with zeros to match the expected number of features
    headers_encoded = np.pad(headers_encoded, (0, 78 - headers_encoded.shape[0]), mode='constant', constant_values=0)

    # Reshape the encoded headers to match the expected input shape
    headers_encoded = headers_encoded.reshape(1, -1)

    response = classifier_model.predict(headers_encoded)

    # Create the label_decoder dictionary with both integer and floating-point keys
    label_decoder = {float(value): label for label, value in dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_))).items()}

    try:
        resp_label = label_decoder[response[0]]
    except KeyError:
        resp_label = "Unknown"

    return {"resp": resp_label, "message": "Request is malicious" if resp_label != "Benign" else "Request is benign"}
@app.route('/')
def home():
    is_malicious = check_request_malicious(request.headers)
    if is_malicious["resp"] != 0:
        # Redirect user if the request is detected as malicious
        return redirect('/malicious')
    else:
        # Return a welcome message if the request is benign
        return jsonify({"message": "Hello, welcome to your feed"})

@app.route('/malicious')
def malicious():
    # Render a template for malicious requests
    return render_template('malicious.html')

if __name__ == '__main__':
    app.run(debug=True)