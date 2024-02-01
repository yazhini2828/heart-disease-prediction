import pandas as pd
from Crypto.Util.Padding import pad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from joblib import load
from .models import LoginData, InputData
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.contrib import messages


def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(data, cipher.algorithm.block_size)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def home(request):
    # Load the encrypted dataset
    encrypted_dataset_path = "C:/Users/yazhini/OneDrive/Pictures/Sujithra mam work/CYBER SECURITY BOOK/encrypted_dataset_n.csv"
    encrypted_df = pd.read_csv(encrypted_dataset_path)

    if request.method == 'POST':
        # Retrieve input values for all 9 features
        age = float(request.POST['age'])
        sex = float(request.POST['sex'])
        cp = float(request.POST['cp'])
        trestbps = float(request.POST['trestbps'])
        chol = float(request.POST['chol'])
        fbs = float(request.POST['fbs'])
        restecg = float(request.POST['restecg'])
        exang = float(request.POST['exang'])
        thal = float(request.POST['thal'])

        # Create a dictionary with input values
        input_data_dict = {
            'age': age,
            'sex': sex,
            'cp': cp,
            'trestbps': trestbps,
            'chol': chol,
            'fbs': fbs,
            'restecg': restecg,
            'exang': exang,
            'thal': thal,
        }

        # Convert the dictionary to a DataFrame
        input_df = pd.DataFrame([input_data_dict])

        # Load the model
        clf = load("C:/Users/yazhini/OneDrive/Pictures/DATA PRIVACY AND SECURITY LAB/CAT 1/clf1.joblib")

        # Make predictions
        result = clf.predict(input_df)

        # Save input data and result
        InputData.objects.create(input_data=encrypt_data(input_df.to_csv(index=False).encode('utf-8'), b'securitykeyyazhi'), result=bool(result))

        # Display the result on the webpage
        messages.success(request, f"Prediction result: {'Heart Disease' if result else 'No Heart Disease'}")

    return render(request, 'predictor/home.html')

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Log in the user and redirect to the home page
            django_login(request, user)
            return HttpResponseRedirect('/home/')
        else:
            # Return an invalid login message or redirect to the login page
            messages.error(request, 'Invalid login credentials. Please try again.')

    return render(request, 'predictor/login.html')

def logout(request):
    # Log out the user
    django_logout(request)
    return HttpResponseRedirect('/login/')
