# Intrusion Detection System using ANN

This project is a graphical Intrusion Detection System (IDS) built with **Python**, **Tkinter GUI**, and an **Artificial Neural Network (ANN)** using `scikit-learn`. It allows users to register/login, upload CSV datasets, train an ANN model, and predict cyber threats in a visually interactive way.


# Features

- User login and registration
- Load and preview CSV datasets
- Train Artificial Neural Network model
- Predict cyber threat categories based on inputs
- Visualize data with charts and heatmaps
- Dark-themed Tkinter GUI for better user experience


# Requirements

Install the required Python libraries with:
```bash
pip install pandas scikit-learn matplotlib seaborn pillow
```


# How to Run

1. Clone this repo or download `project.py`.
2. Place it in a folder with your dataset (CSV format).
3. Run the app:
```bash
python project.py
```
4. Register a user or log in to start using the system.
5. Load your dataset, train the model, and make predictions.


# Supported Dataset Format

- Upload CSV files with **features in columns** and **target in the last column**
- Example structure:
```
feature1, feature2, feature3, ..., threat_type
value1, value2, value3, ..., normal
```

# Sample Screenshots
![image](https://github.com/user-attachments/assets/21d6da0f-316b-4913-b157-ffef702b0cdf)
![image](https://github.com/user-attachments/assets/c3f5857e-7608-442b-9374-c5330b24679f)


# Project Structure

project.py          # Main Python GUI + ANN logic
users.json          # Auto-generated file for user credentials
temp_analysis.png   # Temporary image generated for analysis
pie_chart.png       # Pie chart visualization
heatmap.png         # Heatmap visualization

# Certificate
![Screenshot 2025-06-30 210354](https://github.com/user-attachments/assets/a8bfc49c-5eaa-4142-b836-43efd087ae4b)

```

# Author

**Sai Sujana Donthiri**
