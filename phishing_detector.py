import re
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier # Added RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
import tkinter as tk
from tkinter import ttk, messagebox
import os
from scipy.sparse import hstack, csr_matrix # Explicitly import hstack and csr_matrix here

# --- 1. Dataset Simulation ---
# In a real-world scenario, you would load a large dataset of legitimate and phishing URLs.
# For this example, we'll create a small, simulated dataset.

def create_simulated_dataset():
    """
    Creates a small, simulated dataset of URLs with 'legitimate' and 'phishing' labels.
    Returns a pandas DataFrame.
    """
    data = {
        'url': [
            # Legitimate URLs
            "https://www.google.com",
            "https://www.amazon.com/products/electronics",
            "https://github.com/microsoft/vscode",
            "https://www.nytimes.com/world/africa",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP",
            "https://mail.google.com/mail/u/0/",
            "https://www.wikipedia.org/wiki/Phishing",
            "https://www.example.org/path/to/resource?query=1",
            "https://www.facebook.com/profile",
            "https://www.linkedin.com/in/john-doe",
            "https://docs.python.org/3/library/re.html",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://www.twitter.com/elonmusk",

            # Phishing URLs (simulated characteristics)
            "http://192.168.1.1/login.html", # IP address in URL
            "http://paypal.com.login.com/webscr.php", # Subdomain manipulation
            "https://security-update.myaccount.com@phishing-site.ru/login", # @ symbol
            "http://bankofamerica.com.secure-login-update.info/sign-in.php", # Domain with hyphen, long URL
            "http://login.microsoft.com.secure-verify.xyz/signin",
            "http://www.evil-site.com/amazon/signin?param=value",
            "https://googl.com-support.net/verify-account",
            "http://facebook-login-help.biz/confirm",
            "https://www.wellsfargo.com.secure-access.info/update",
            "http://bit.ly/2sFgT1l", # Shortened URL (can be suspicious)
            "http://www.login-confirm-portal.com/update-info",
            "https://update-security-account.ru/login.php",
            "http://secure-login-panel.xyz/verify",
            "https://support.apple.com-security.org/login"
        ],
        'label': [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, # Legitimate (0)
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1  # Phishing (1)
        ]
    }
    df = pd.DataFrame(data)
    return df

# --- 2. Rule-Based Detection ---

def is_ip_address(domain):
    """Checks if the domain is an IP address."""
    # Regex to match IPv4 or IPv6 (simplified)
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
    return bool(ip_pattern.match(domain))

def rule_based_detection(url):
    """
    Flags a URL as suspicious based on a set of heuristic rules.
    Returns True if suspicious, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query

        # Rule 1: Check for IP address in hostname (often used in phishing)
        if is_ip_address(domain):
            return True, "IP address in hostname"

        # Rule 2: Long URL (phishers often use long URLs to hide true domain)
        if len(url) > 75: # Arbitrary threshold, can be tuned
            return True, "Long URL"

        # Rule 3: Presence of '@' symbol (can indicate credential stuffing)
        if '@' in parsed_url.netloc:
            return True, "'@' symbol in URL"

        # Rule 4: Presence of sensitive keywords in subdomains/paths (e.g., 'login', 'secure', 'bank' in unusual positions)
        keywords = ['login', 'signin', 'secure', 'account', 'verify', 'bank', 'paypal', 'microsoft', 'google', 'apple']
        for keyword in keywords:
            if keyword in domain.lower() and keyword not in ["google.com", "microsoft.com", "apple.com", "paypal.com"] and not domain.endswith(f"{keyword}.com"):
                # Heuristic: Check if keyword is not part of a legitimate common domain but present
                return True, f"Suspicious keyword '{keyword}' in domain"
            if keyword in path.lower() and len(path) > 15: # If keyword is deep in a long path
                return True, f"Suspicious keyword '{keyword}' in long path"

        # Rule 5: Non-standard ports (can indicate malicious intent)
        # This is harder to check directly without making HTTP requests, but we can look for explicit port numbers
        if parsed_url.port and parsed_url.port not in [80, 443]:
            return True, "Non-standard port"

        # Rule 6: Absence of HTTPS for sensitive operations (less common now, but still a check)
        if url.startswith('http://') and any(kw in url.lower() for kw in ['login', 'account', 'bank']):
            return True, "HTTP with sensitive keyword"

        # Rule 7: Excessive number of subdomains (e.g., bankofamerica.com.secure-login-update.info)
        parts = domain.split('.')
        if len(parts) > 5: # Arbitrary threshold
            return True, "Excessive subdomains"

        # Rule 8: Use of URL shorteners (can hide true destination)
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']
        if any(s in domain for s in shorteners):
            return True, "URL shortener detected"


    except Exception as e:
        print(f"Error in rule-based detection for {url}: {e}")
        return False, "Error during analysis"

    return False, "No suspicious rules matched"

# --- 3. AI (Machine Learning) Detection ---

class PhishingDetectorAI: # Renamed class to PhishingDetectorAI
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.features = ['url_length', 'num_dots', 'has_https', 'has_ip', 'has_at_symbol', 'num_dashes_in_domain', 'num_subdomains']

    def extract_features(self, url):
        """
        Extracts various features from a URL for AI model.
        """
        parsed = urlparse(url)
        domain = parsed.netloc

        url_length = len(url)
        num_dots = url.count('.')
        has_https = 1 if parsed.scheme == 'https' else 0
        has_ip = 1 if is_ip_address(domain) else 0 # Re-use IP check from rule-based
        has_at_symbol = 1 if '@' in url else 0
        num_dashes_in_domain = domain.count('-')
        num_subdomains = len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0 # simplified

        # Return a dictionary of features for easy DataFrame conversion
        return {
            'url_length': url_length,
            'num_dots': num_dots,
            'has_https': has_https,
            'has_ip': has_ip,
            'has_at_symbol': has_at_symbol,
            'num_dashes_in_domain': num_dashes_in_domain,
            'num_subdomains': num_subdomains
        }

    def train_model(self, df):
        """
        Trains a RandomForestClassifier (AI model) on the provided DataFrame.
        The DataFrame must contain 'url' and 'label' columns.
        """
        print("Starting AI model training...") # Updated print

        # Feature Engineering: Extract numerical features
        extracted_features_list = [self.extract_features(url) for url in df['url']]
        features_df = pd.DataFrame(extracted_features_list)
        X_numerical = features_df[self.features]

        # Convert numerical features to a sparse matrix to ensure compatibility with hstack
        X_numerical_sparse = csr_matrix(X_numerical.values)
        print(f"Shape of X_numerical_sparse: {X_numerical_sparse.shape}") # Debug print

        # Text Feature Engineering: Using TF-IDF on the URL string itself
        self.vectorizer = TfidfVectorizer(max_features=1000, lowercase=True)
        X_text = self.vectorizer.fit_transform(df['url'])
        print(f"Shape of X_text: {X_text.shape}") # Debug print

        # --- IMPORTANT CHECK ---
        if X_numerical_sparse.shape[0] != X_text.shape[0]:
            raise ValueError(
                f"Mismatch in number of samples! X_numerical_sparse has {X_numerical_sparse.shape[0]} rows "
                f"while X_text has {X_text.shape[0]} rows. They must be equal."
            )
        # --- END IMPORTANT CHECK ---

        # Combine numerical and text features (both are now sparse matrices)
        X = hstack([X_numerical_sparse, X_text])
        print(f"Shape of combined X: {X.shape}") # Debug print


        y = df['label']

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        # Initialize and train the RandomForestClassifier model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        self.model.fit(X_train, y_train)

        # Evaluate the model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])

        print(f"AI Model Training Complete. Accuracy: {accuracy:.4f}") # Updated print
        print("Classification Report:\n", report)
        print("AI model is ready for predictions.") # Updated print

    def predict(self, url):
        """
        Predicts whether a given URL is phishing or legitimate using the trained AI model.
        Returns 1 for phishing, 0 for legitimate.
        """
        if self.model is None or self.vectorizer is None:
            raise ValueError("AI model not trained. Please call train_model() first.") # Updated error message

        # Extract numerical features for the single URL
        features_numerical = pd.DataFrame([self.extract_features(url)])[self.features]
        # Convert numerical features to a sparse matrix
        features_numerical_sparse = csr_matrix(features_numerical.values)

        # Transform the URL text using the *trained* vectorizer
        features_text = self.vectorizer.transform([url])

        # Combine features
        X_predict = hstack([features_numerical_sparse, features_text])

        prediction = self.model.predict(X_predict)[0]
        # Get probability to show confidence (RandomForestClassifier also has predict_proba)
        probability = self.model.predict_proba(X_predict)[0]
        phishing_prob = probability[1] # Probability of being phishing (label 1)

        return prediction, phishing_prob

# --- 4. Tkinter GUI ---

class PhishingDetectorGUI:
    def __init__(self, master):
        self.master = master
        master.title("Phishing Website Detector")
        master.geometry("800x600")
        master.resizable(True, True)

        # Configure styles using ttk
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f2f5") # Light grey background for frames
        self.style.configure("TLabel", background="#f0f2f5", foreground="#333333", font=("Inter", 12)) # Dark text on light grey
        self.style.configure("TButton",
                             font=("Inter", 12, "bold"),
                             padding=10,
                             borderwidth=0,
                             relief="flat",
                             foreground="white",
                             background="#007bff") # Blue buttons
        self.style.map("TButton",
                       background=[('active', '#0056b3')], # Darker blue on hover/active
                       foreground=[('active', 'white')])
        self.style.configure("TEntry", font=("Inter", 12), padding=5, fieldbackground="white", foreground="#333333")
        # Note: TText is a standard tkinter widget, not ttk, so 'background' and 'foreground' are direct options
        # It's configured below directly on the widget itself.

        # Set up AI model
        self.ai_detector = PhishingDetectorAI() # Changed to ai_detector
        self.training_complete = False
        self.master.after(100, self.train_ai_model_async) # Changed to train_ai_model_async

        self.create_widgets()

    def train_ai_model_async(self): # Renamed function
        """Trains the AI model in a non-blocking way."""
        try:
            messagebox.showinfo("Training AI Model", "Training artificial intelligence model. This might take a moment...") # Updated message
            df = create_simulated_dataset()
            self.ai_detector.train_model(df) # Changed to ai_detector
            self.training_complete = True
            messagebox.showinfo("Training Complete", "Artificial intelligence model training finished successfully!") # Updated message
        except Exception as e:
            messagebox.showerror("AI Training Error", f"Failed to train AI model: {e}") # Updated message
            self.training_complete = False

    def create_widgets(self):
        """Creates and places all GUI widgets."""
        # Main frame
        main_frame = ttk.Frame(self.master, padding="20", style="TFrame")
        main_frame.pack(fill="both", expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Phishing Website Detector", font=("Inter", 24, "bold"),
                                background="#f0f2f5", foreground="#333333")
        title_label.pack(pady=20)

        # URL Input Frame
        input_frame = ttk.Frame(main_frame, padding="15", relief="groove", borderwidth=2, style="TFrame")
        input_frame.pack(pady=10, fill="x", padx=20)

        url_label = ttk.Label(input_frame, text="Enter URL:", style="TLabel")
        url_label.pack(pady=5, anchor="w")

        self.url_entry = ttk.Entry(input_frame, width=80, style="TEntry")
        self.url_entry.pack(pady=5, fill="x", expand=True)
        self.url_entry.bind("<Return>", lambda event: self.check_url()) # Allow pressing Enter

        # Buttons Frame
        button_frame = ttk.Frame(main_frame, padding="10", style="TFrame")
        button_frame.pack(pady=10)

        check_button = ttk.Button(button_frame, text="Check URL", command=self.check_url)
        check_button.grid(row=0, column=0, padx=10)

        clear_button = ttk.Button(button_frame, text="Clear", command=self.clear_results)
        clear_button.grid(row=0, column=1, padx=10)

        # Results Frame
        results_frame = ttk.Frame(main_frame, padding="15", relief="groove", borderwidth=2, style="TFrame")
        results_frame.pack(pady=10, fill="both", expand=True, padx=20)

        results_label = ttk.Label(results_frame, text="Detection Results:", font=("Inter", 14, "bold"),
                                  background="#f0f2f5", foreground="#333333")
        results_label.pack(pady=5, anchor="w")

        self.results_text = tk.Text(results_frame, wrap="word", height=15, width=70, state="disabled", font=("Inter", 11),
                                     background="#e9ecef", foreground="#343a40", relief="flat", borderwidth=0, padx=10, pady=10)
        self.results_text.pack(pady=5, fill="both", expand=True)

        # Scrollbar for results
        scrollbar = ttk.Scrollbar(self.results_text, command=self.results_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.results_text.config(yscrollcommand=scrollbar.set)

    def display_result(self, method, status, reason="", probability=None):
        """Helper to display results in the text widget."""
        self.results_text.config(state="normal")
        self.results_text.insert(tk.END, f"--- {method} ---\n")
        if status == "Legitimate":
            self.results_text.insert(tk.END, f"Status: ✅ {status}\n", "legitimate")
        elif status == "Phishing":
            self.results_text.insert(tk.END, f"Status: ❌ {status}\n", "phishing")
        else:
            self.results_text.insert(tk.END, f"Status: {status}\n")

        if reason:
            self.results_text.insert(tk.END, f"Reason: {reason}\n")
        if probability is not None:
            self.results_text.insert(tk.END, f"Confidence (Phishing Probability): {probability:.2f}\n")
        self.results_text.insert(tk.END, "\n")
        self.results_text.config(state="disabled")
        self.results_text.see(tk.END) # Scroll to the end

        # Define tags for styling with direct colors
        self.results_text.tag_config("legitimate", foreground="green", font=("Inter", 11, "bold"))
        self.results_text.tag_config("phishing", foreground="red", font=("Inter", 11, "bold"))


    def check_url(self):
        """Performs both rule-based and AI-based detection on the entered URL.""" # Updated comment
        url = self.url_entry.get().strip()
        self.clear_results() # Clear previous results

        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return

        # Initialize ml_prediction and ml_probability to None (or a default)
        ai_prediction = None # Changed to ai_prediction
        ai_probability = None # Changed to ai_probability

        # Validate URL format slightly
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url # Prepend a scheme if missing for parsing

        self.display_result("Input URL", url)

        # Rule-based detection
        is_suspicious_rule, reason_rule = rule_based_detection(url)
        rule_status = "Phishing" if is_suspicious_rule else "Legitimate"
        self.display_result("Rule-Based Detection", rule_status, reason_rule)

        # AI-based detection
        if not self.training_complete:
            self.display_result("AI-Based Detection", "Model not yet trained. Please wait.") # Updated text
        else:
            try:
                ai_prediction, ai_probability = self.ai_detector.predict(url) # Changed to ai_detector
                ai_status = "Phishing" if ai_prediction == 1 else "Legitimate"
                self.display_result("AI-Based Detection", ai_status, "", ai_probability) # Updated text
            except Exception as e:
                self.display_result("AI-Based Detection", "Error during prediction", f"Error: {e}") # Updated text
                # Keep ai_prediction as None or set to a value indicating failure if needed
                ai_prediction = -1 # Use -1 to indicate an error or non-prediction

        # Final Verdict (simple aggregation)
        final_verdict = "UNCLEAR"
        # Check if ai_prediction was successfully assigned a value (not None or -1)
        if is_suspicious_rule and ai_prediction == 1: # Changed to ai_prediction
            final_verdict = "PHISHING (High Confidence)"
        elif is_suspicious_rule or (ai_prediction == 1 if ai_prediction is not None and ai_prediction != -1 else False): # Changed to ai_prediction
            final_verdict = "SUSPICIOUS (Needs Review)"
        else:
            # If AI prediction failed or didn't run, base verdict primarily on rule-based or default to legitimate
            if ai_prediction == -1: # Changed to ai_prediction
                final_verdict = "AI Prediction Failed - Rule-Based Only" # Updated text
            elif is_suspicious_rule: # Only rule-based flagged it
                 final_verdict = "SUSPICIOUS (Rule-Based Only)"
            else: # Neither flagged it or AI didn't run and rules didn't flag
                final_verdict = "LEGITIMATE (Likely Safe)"


        self.results_text.config(state="normal")
        self.results_text.insert(tk.END, f"\n--- OVERALL VERDICT ---\n", "verdict_header")
        if "PHISHING" in final_verdict:
            self.results_text.insert(tk.END, f"Verdict: {final_verdict}\n", "verdict_phishing")
        elif "SUSPICIOUS" in final_verdict or "Failed" in final_verdict: # Also highlight failed as suspicious
            self.results_text.insert(tk.END, f"Verdict: {final_verdict}\n", "verdict_suspicious")
        else:
            self.results_text.insert(tk.END, f"Verdict: {final_verdict}\n", "verdict_legitimate")
        self.results_text.config(state="disabled")

        # Define tags for verdict styling with direct colors
        self.results_text.tag_config("verdict_header", font=("Inter", 12, "bold", "underline"), foreground="#007bff")
        self.results_text.tag_config("verdict_phishing", font=("Inter", 16, "bold"), foreground="darkred")
        self.results_text.tag_config("verdict_suspicious", font=("Inter", 16, "bold"), foreground="orange")
        self.results_text.tag_config("verdict_legitimate", font=("Inter", 16, "bold"), foreground="darkgreen")


    def clear_results(self):
        """Clears the results text area."""
        self.results_text.config(state="normal")
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state="disabled")

# Main execution block
if __name__ == "__main__":
    # Ensure scikit-learn and pandas are installed:
    # pip install scikit-learn pandas

    # Tkinter setup
    root = tk.Tk()
    app = PhishingDetectorGUI(root)
    root.mainloop()
