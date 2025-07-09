import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, ttk
from PIL import Image, ImageTk
import pandas as pd
import os
import json
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.neural_network import MLPClassifier
import matplotlib.pyplot as plt
import seaborn as sns

class IntrusionDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🚨 Intrusion Detection System - ANN")
        self.root.geometry("1000x700")

        self.bg_color = "#121212"
        self.fg_color = "#ffffff"
        self.btn_color = "#1e1e1e"
        self.highlight_color = "#3a3a3a"

        self.root.configure(bg=self.bg_color)

        self.model = None
        self.scaler = StandardScaler()
        self.encoder = LabelEncoder()
        self.columns = []
        self.user_file = "users.json"
        self.logged_user = None
        self.data_files = []

        self.load_users()
        self.login_screen()

    def load_users(self):
        if os.path.exists(self.user_file):
            with open(self.user_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = {}

    def save_users(self):
        with open(self.user_file, 'w') as f:
            json.dump(self.users, f)

    def login_screen(self):
        self.login_frame = tk.Frame(self.root, bg=self.bg_color)
        self.login_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(self.login_frame, text="User Login", font=("Helvetica", 24, "bold"), pady=10, fg=self.fg_color, bg=self.bg_color).pack(pady=20)
        tk.Label(self.login_frame, text="Username", fg=self.fg_color, bg=self.bg_color).pack()
        self.username_entry = tk.Entry(self.login_frame, width=30)
        self.username_entry.pack(pady=5)

        tk.Label(self.login_frame, text="Password", fg=self.fg_color, bg=self.bg_color).pack()
        self.password_entry = tk.Entry(self.login_frame, show="*", width=30)
        self.password_entry.pack(pady=5)

        login_btn = tk.Button(self.login_frame, text="Login", command=self.verify_login, width=20, bg=self.btn_color, fg=self.fg_color, activebackground=self.highlight_color)
        login_btn.pack(pady=10)

        register_btn = tk.Button(self.login_frame, text="Register", command=self.register_user, width=20, bg=self.btn_color, fg=self.fg_color, activebackground=self.highlight_color)
        register_btn.pack(pady=5)

    def register_user(self):
        def save_new_user():
            user = reg_username.get()
            pwd = reg_password.get()
            if user and pwd:
                if user in self.users:
                    messagebox.showerror("Error", "Username already exists!")
                else:
                    self.users[user] = pwd
                    self.save_users()
                    reg_window.destroy()
                    messagebox.showinfo("Success", "User registered successfully")
            else:
                messagebox.showerror("Error", "Fields cannot be empty")

        reg_window = Toplevel(self.root)
        reg_window.title("Register")
        reg_window.configure(bg=self.bg_color)
        tk.Label(reg_window, text="New Username", fg=self.fg_color, bg=self.bg_color).pack()
        reg_username = tk.Entry(reg_window)
        reg_username.pack(pady=5)
        tk.Label(reg_window, text="New Password", fg=self.fg_color, bg=self.bg_color).pack()
        reg_password = tk.Entry(reg_window, show="*")
        reg_password.pack(pady=5)
        tk.Button(reg_window, text="Register", command=save_new_user, bg=self.btn_color, fg=self.fg_color, activebackground=self.highlight_color).pack(pady=10)

    def verify_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username in self.users and self.users[username] == password:
            self.logged_user = username
            self.login_frame.destroy()
            self.build_main_ui()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def build_main_ui(self):
        self.tab_control = ttk.Notebook(self.root)
        self.tab_control.pack(expand=1, fill="both")

        self.home_tab = tk.Frame(self.tab_control, bg=self.bg_color)
        self.settings_tab = tk.Frame(self.tab_control, bg=self.bg_color)
        self.history_tab = tk.Frame(self.tab_control, bg=self.bg_color)
        self.dataset_tab = tk.Frame(self.tab_control, bg=self.bg_color)
        self.analysis_tab = tk.Frame(self.tab_control, bg=self.bg_color)

        self.tab_control.add(self.analysis_tab, text='📈 Threat Analysis')
        self.build_analysis_tab()

        self.tab_control.add(self.home_tab, text='🏠 Home')
        self.tab_control.add(self.settings_tab, text='⚙️ Settings')
        self.tab_control.add(self.history_tab, text='📜 History')
        self.tab_control.add(self.dataset_tab, text='🗂️ Datasets')

        self.build_home_tab()
        self.build_settings_tab()

    def build_home_tab(self):
        tk.Label(self.home_tab, text="Cyber Threat Intrusion Detection Dashboard", font=("Helvetica", 20, "bold"), pady=10, fg=self.fg_color, bg=self.bg_color).pack(fill=tk.X)

        self.button_frame = tk.Frame(self.home_tab, bg=self.bg_color)
        self.button_frame.pack(side=tk.LEFT, fill=tk.Y, padx=20, pady=20)

        buttons = [
            ("📂 Load CSV", self.load_data),
            ("🧠 Train ANN Model", self.train_model),
            ("📊 View Data Analysis", self.show_analysis),
            ("⚡ Predict", self.predict),
            ("🔄 Refresh Input", self.refresh_input_fields)
        ]

        for label, cmd in buttons:
            btn = tk.Button(self.button_frame, text=label, command=cmd, width=25, bg=self.btn_color, fg=self.fg_color, activebackground=self.highlight_color)
            btn.pack(pady=10)

        self.input_frame = tk.Frame(self.home_tab, bg=self.bg_color)
        self.input_frame.pack(pady=10)
        self.entries = []

        self.result_label = tk.Label(self.home_tab, text="", font=("Helvetica", 16), fg="lightgreen", bg=self.bg_color)
        self.result_label.pack(pady=10)

    def build_settings_tab(self):
        def change_password():
            current_pwd = current_password.get()
            new_pwd = new_password.get()
            if self.users[self.logged_user] == current_pwd:
                self.users[self.logged_user] = new_pwd
                self.save_users()
                messagebox.showinfo("Success", "Password changed")
            else:
                messagebox.showerror("Error", "Current password incorrect")

        tk.Label(self.settings_tab, text="Change Password", font=("Helvetica", 14), fg=self.fg_color, bg=self.bg_color).pack(pady=10)
        current_password = tk.Entry(self.settings_tab, show="*")
        current_password.pack(pady=5)
        new_password = tk.Entry(self.settings_tab, show="*")
        new_password.pack(pady=5)
        tk.Button(self.settings_tab, text="Update Password", command=change_password, bg=self.btn_color, fg=self.fg_color, activebackground=self.highlight_color).pack(pady=10)

    def load_data(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if file_path:
            self.data = pd.read_csv(file_path)
            self.data_files.append(os.path.basename(file_path))
            self.columns = list(self.data.columns[:-1])
            self.target_col = self.data.columns[-1]

            for widget in self.input_frame.winfo_children():
                widget.destroy()

            self.entries = []
            for col in self.columns:
                tk.Label(self.input_frame, text=col, fg=self.fg_color, bg=self.bg_color).pack()
                entry = tk.Entry(self.input_frame, width=30)
                entry.pack(pady=2)
                self.entries.append(entry)

            messagebox.showinfo("Data Loaded", f"Loaded dataset with {len(self.columns)} features.")
            self.update_dataset_tab()

    def update_dataset_tab(self):
        for widget in self.dataset_tab.winfo_children():
            widget.destroy()
        tk.Label(self.dataset_tab, text="Uploaded Datasets", font=("Helvetica", 14), fg=self.fg_color, bg=self.bg_color).pack(pady=10)
        for file in self.data_files:
            tk.Label(self.dataset_tab, text=file, fg=self.fg_color, bg=self.bg_color).pack()

    def train_model(self):
        if not hasattr(self, 'data'):
            messagebox.showerror("Error", "Load data first!")
            return

        X = self.data.iloc[:, :-1]
        y = self.data.iloc[:, -1]

        for col in X.select_dtypes(include='object').columns:
            X[col] = LabelEncoder().fit_transform(X[col])

        if y.dtype == 'object':
            y = self.encoder.fit_transform(y)

        X = self.scaler.fit_transform(X)
        self.model = MLPClassifier(hidden_layer_sizes=(16, 16), max_iter=500)
        self.model.fit(X, y)

        accuracy = self.model.score(X, y)
        messagebox.showinfo("Model Trained", f"Accuracy on full dataset: {accuracy * 100:.2f}%")

    def predict(self):
        if not self.model:
            messagebox.showerror("Error", "Train the model first!")
            return

        try:
            input_data = [float(entry.get()) for entry in self.entries]
            input_scaled = self.scaler.transform([input_data])
            pred = self.model.predict(input_scaled)[0]
            label = self.encoder.inverse_transform([pred])[0] if hasattr(self.encoder, 'classes_') else pred
            self.result_label.config(text=f"Prediction: {label}", fg="lightgreen")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {e}")

    def refresh_input_fields(self):
        for entry in self.entries:
            entry.delete(0, tk.END)
        self.result_label.config(text="")

    def show_analysis(self):
        if not hasattr(self, 'data'):
            messagebox.showerror("Error", "Load data first!")
            return

        top = Toplevel(self.root)
        top.title("📊 Data Analysis")
        top.geometry("720x420")
        top.configure(bg=self.bg_color)

        plt.style.use('dark_background')
        plt.figure(figsize=(7, 4))
        try:
            sns.countplot(x=self.target_col, data=self.data, palette="coolwarm")
            plt.title("Threat Distribution")
            plt.tight_layout()
            plot_path = "temp_analysis.png"
            plt.savefig(plot_path)
            plt.close()

            img = Image.open(plot_path)
            img = img.resize((700, 400))
            img_tk = ImageTk.PhotoImage(img)
            label_img = tk.Label(top, image=img_tk, bg=self.bg_color)
            label_img.image = img_tk
            label_img.pack()
        except Exception as e:
            messagebox.showerror("Error", f"Could not generate plot: {e}")
            top.destroy()

    def build_analysis_tab(self):
        def render_threat_pie_and_heatmap():
            if not hasattr(self, 'data'):
                return
            for widget in self.analysis_tab.winfo_children():
                widget.destroy()

            plt.figure(figsize=(4, 4))
            self.data[self.target_col].value_counts().plot.pie(autopct='%1.1f%%', colors=sns.color_palette('Set2'))
            plt.title("Threat Distribution")
            plt.ylabel('')
            pie_path = "pie_chart.png"
            plt.tight_layout()
            plt.savefig(pie_path)
            plt.close()

            numeric_data = self.data.select_dtypes(include=['int64', 'float64']).dropna(axis=1)
            plt.figure(figsize=(6, 4))
            sns.heatmap(numeric_data.corr(), annot=True, cmap="coolwarm", fmt=".2f")
            plt.title("Feature Correlation")
            heatmap_path = "heatmap.png"
            plt.tight_layout()
            plt.savefig(heatmap_path)
            plt.close()

            pie_img = Image.open(pie_path)
            pie_img = pie_img.resize((300, 300))
            pie_img = ImageTk.PhotoImage(pie_img)
            pie_label = tk.Label(self.analysis_tab, image=pie_img, bg=self.bg_color)
            pie_label.image = pie_img
            pie_label.grid(row=0, column=0, padx=20, pady=10)

            heat_img = Image.open(heatmap_path)
            heat_img = heat_img.resize((400, 300))
            heat_img = ImageTk.PhotoImage(heat_img)
            heat_label = tk.Label(self.analysis_tab, image=heat_img, bg=self.bg_color)
            heat_label.image = heat_img
            heat_label.grid(row=0, column=1, padx=20, pady=10)

        self.tab_control.bind("<<NotebookTabChanged>>", lambda event: render_threat_pie_and_heatmap() if self.tab_control.select() == self.tab_control.tabs()[0] else None)

if __name__ == "__main__":
    root = tk.Tk()
    app = IntrusionDetectionApp(root)
    root.mainloop()
