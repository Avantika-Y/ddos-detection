from flask import Flask, render_template, request
import pickle

# Load your trained models (replace with actual model instances)
# For demonstration, assuming the models are already loaded into memory
import pickle

# Load the trained models using pickle
with open('svm_model.pkl', 'rb') as f:
    svm_model = pickle.load(f)

with open('knn_model.pkl', 'rb') as f:
    knn_model = pickle.load(f)

with open('nb_model.pkl', 'rb') as f:
    nb_model = pickle.load(f)

with open('rf_model.pkl', 'rb') as f:
    rf_model = pickle.load(f)

app = Flask(__name__)

def preprocess_data(log):
    """
    Preprocesses the network log data to match the format expected by the models.

    Args:
        log (dict): A dictionary containing network log attributes.

    Returns:
        array-like: Preprocessed data ready for prediction.
    """
    # Extract relevant features from the log dictionary
    processed_data = [
        log["PKT_RATE"], log["PKT_SIZE"], log["NUMBER_OF_PKT"],
        log["FLAGS_SF"], log["FLAGS_S0"], log["FLAGS_SA"],
        log["FLAGS_RA"], log["FLAGS_PA"], log["FLAGS_FRA"],
        log["FLAGS_SF2"], log["FLAGS_REJ"], log["FLAGS_RSTO"],
        log["FLAGS_RSTOS0"], log["FLAGS_RSTR"], log["FLAGS_S2"],
        log["FLAGS_S1"], log["FLAGS_OTH"], log["DURATION"],
        log["SRC_BYTES"], log["DST_BYTES"], log["LAND"],
        log["WRONG_FRAGMENT"], log["URGENT"], log["HOT"],
        log["NUM_FAILED_LOGINS"], log["IS_HOST_LOGIN"],
        log["IS_GUEST_LOGIN"]
    ]
    return processed_data

def predict_ddos(log):
    """
    Predicts if a network log is a potential DDoS using loaded models.

    Args:
        log (dict): A dictionary containing network log attributes.

    Returns:
        str: "DDoS" if potential DDoS, "Normal" otherwise.
    """
    try:
        # Preprocess the log data
        processed_log = preprocess_data(log)

        # Extract 'hot' and 'new_attribute' from the log data
        hot = log["HOT"]
       

        # Make predictions with each model
        svm_pred = svm_model.predict([processed_log])[0]
        knn_pred = knn_model.predict([processed_log])[0]
        nb_pred = nb_model.predict([processed_log])[0]
        rf_pred = rf_model.predict([processed_log])[0]

        # Implement your chosen ensemble approach (e.g., majority vote)
        if sum([svm_pred, knn_pred, nb_pred, rf_pred]) >= 3 and hot==0: 
            return "DDoS"
        else:
            return "Normal"
        
    except Exception as e:
        # Handle any errors gracefully
        return f"Error: {e}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/result', methods=['POST'])
def result():
    if request.method == 'POST':
        # Get the form data
        log = {
            "PKT_RATE": int(request.form['pkt_rate']),
            "PKT_SIZE": int(request.form['pkt_size']),
            "NUMBER_OF_PKT": int(request.form['number_of_pkt']),
            "FLAGS_SF": int(request.form['flags_sf']),
            "FLAGS_S0": int(request.form['flags_s0']),
            "FLAGS_SA": int(request.form['flags_sa']),
            "FLAGS_RA": int(request.form['flags_ra']),
            "FLAGS_PA": int(request.form['flags_pa']),
            "FLAGS_FRA": int(request.form['flags_fra']),
            "FLAGS_SF2": int(request.form['flags_sf2']),
            "FLAGS_REJ": int(request.form['flags_rej']),
            "FLAGS_RSTO": int(request.form['flags_rsto']),
            "FLAGS_RSTOS0": int(request.form['flags_rstos0']),
            "FLAGS_RSTR": int(request.form['flags_rstr']),
            "FLAGS_S2": int(request.form['flags_s2']),
            "FLAGS_S1": int(request.form['flags_s1']),
            "FLAGS_OTH": int(request.form['flags_oth']),
            "DURATION": int(request.form['duration']),
            "SRC_BYTES": int(request.form['src_bytes']),
            "DST_BYTES": int(request.form['dst_bytes']),
            "LAND": int(request.form['land']),
            "WRONG_FRAGMENT": int(request.form['wrong_fragment']),
            "URGENT": int(request.form['urgent']),
            "HOT": int(request.form['hot']),
            "NUM_FAILED_LOGINS": int(request.form['num_failed_logins']),
            "IS_HOST_LOGIN": int(request.form['is_host_login']),
            "IS_GUEST_LOGIN": int(request.form['is_guest_login']),
            
        }
        prediction = predict_ddos(log)
        return render_template('result.html', prediction=prediction)

if __name__ == '__main__':
    app.run(debug=True)
