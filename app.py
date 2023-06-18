import os
import json
import firebase_admin
from firebase_admin import credentials, db
from flask import Flask, request, render_template, jsonify
from Crypto.Cipher import ARC4
import ast
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, session
import pyrebase
import random
import math
import os
from werkzeug.utils import secure_filename
import base64
import tempfile
import uuid
import firebase_admin
from datetime import datetime
from markupsafe import Markup
import requests
import json


airflow=3
heart_beat=102
ecgdata=61
temp=97
gsrdata=51

key = b'1234567891234567'


def acornEncryption(key,initialData):
  cipher = ARC4.new(key)
  encryptedData = {}
  keys = ['airflow', 'heart_beat', 'ecgdata', 'temp', 'gsrdata']
  for i in keys:
    plaintext_bytes = str(initialData[i]).encode('utf-8')
    ciphertext = cipher.encrypt(plaintext_bytes)
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    encryptedData[i]=ciphertext_base64
  return encryptedData



def acornDecryption(key, encrylist):
  cipher = ARC4.new(key)
  decryptedData = {}
  keys = ['airflow', 'heart_beat', 'ecgdata', 'temp', 'gsrdata']
  for i, key in enumerate(keys):
      ciphertext = base64.b64decode(encrylist[i])
      plaintext = cipher.decrypt(ciphertext)
      plaintext_str = plaintext.decode('utf-8',errors='ignore')
      decryptedData[key] = plaintext_str
  print(decryptedData)
  return decryptedData




initialData={'airflow':airflow,
             'heart_beat':heart_beat,
             'ecgdata':ecgdata,
             'temp':temp,
             'gsrdata':gsrdata}


# Initialize the Flask app
app = Flask(__name__, static_folder='static')
# Initialize the Firebase app

app.secret_key = "projectibmgroup1"
firebase_config = {
    "apiKey": "AIzaSyACWpAVtpdZmXMCvtq-RlHx8pp3SOergiY",
    "authDomain": "healthrpi.firebaseapp.com",
    "databaseURL": "https://healthrpi-default-rtdb.firebaseio.com",
    "projectId": "healthrpi",
    "storageBucket": "healthrpi.appspot.com",
    "messagingSenderId": "695243921609",
    "appId": "1:695243921609:web:761b1f3f311d4bbcffd518"
}

firebase = pyrebase.initialize_app(firebase_config)
storage = firebase.storage()
auth = firebase.auth()

# Define the route for the data retrieval page
@app.route('/', methods=['GET', 'POST'])
def landing_page():
    return render_template('index.html')

@app.route('/patient_data', methods=['GET','POST'])
def patient_data():
    user_id = session.get('user_id')
    if user_id:
        encryptedData = acornEncryption(key, initialData)
        response = firebase.database().child("patients").child(user_id).get()
        username = response.val().get('username')
        if request.method == 'POST':
            firebase.database().child("patientdata").child(user_id).set({
                'pid': username,
                'airflow':encryptedData['airflow'],
                'heart_beat':encryptedData['heart_beat'],
                'ecgdata':encryptedData['ecgdata'],
                'temp':encryptedData['temp'],
                'gsrdata':encryptedData['gsrdata']
  })
            return redirect(url_for('success'))
        return render_template('patientdata.html', data=encryptedData)
    else:
        return redirect(url_for('patient_login'))


@app.route('/data', methods=['GET'])
def data():
    doctor_user_id = session.get('user_id')
    if doctor_user_id :
        patient_id_from_session = session.get('pid')
        patient_details_response = firebase.database().child("patientdata").child(patient_id_from_session).get()
        encryptedDataList = []
        encryptedDataList.append( patient_details_response.val()['airflow'])
        encryptedDataList.append(patient_details_response.val()['ecgdata'])
        encryptedDataList.append( patient_details_response.val()['gsrdata'])
        encryptedDataList.append(patient_details_response.val()['heart_beat'])
        encryptedDataList.append(patient_details_response.val()['temp'])
        print(encryptedDataList)
        decryptedData = acornDecryption(key,encryptedDataList)
        return render_template('data.html', data=decryptedData)


@app.route('/patient_id', methods=['GET','POST'])
def patient_id():
    doctor_user_id = session.get('user_id')
    if doctor_user_id and request.method == 'GET':
        return render_template('patient_id.html')
    elif request.method == 'POST':
        pid = request.form['pid']
        try:
            # Get user record from database
            patients = firebase.database().child('patients').get()
            # Check if user exists and password is correct
            for patient in patients.each():
                if patient.val()['username'] == str(pid):
                    print(patient.val()['username'], pid)
                    session['pid'] = patient.key()
                    print(patient)
                    return redirect(url_for('data'))
            # Handle login error
            flash('Invalid Patient ID... Try Again', 'error')
            return render_template('patient_id.html')
        except:
            # Handle login error
            flash('Invalid Username or Password. Try Again...', 'error')
            return render_template('patient_id.html')
    else:
        return redirect(url_for('doctor_login'))


@app.route('/patient_login', methods=['GET', 'POST'])
def patient_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print()

        # Authenticate user with Firebase
        try:
            # Get user record from database
            users = firebase.database().child('patients').get()
            # Check if user exists and password is correct
            for user in users.each():
                if user.val()['username'] == username and user.val()['password'] == password:
                    # Save user ID to session
                    session['user_id'] = user.key()
                    return redirect(url_for('patient_data'))
            # Handle login error
            flash('Invalid Username or Password. Try Again...', 'error')
            return render_template('patientlogin.html')
        except:
            # Handle login error
            flash('Invalid Username or Password. Try Again...', 'error')
            return render_template('patientlogin.html')
    else:
        # This is a GET request, so render the login form
        return render_template('patientlogin.html')

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Authenticate user with Firebase
        try:
            # Get user record from database
            users = firebase.database().child('doctors').get()
            # Check if user exists and password is correct
            for user in users.each():
                if user.val()['username'] == username and user.val()['password'] == password:
                    # Save user ID to session
                    session['user_id'] = user.key()
                    return redirect(url_for('patient_id'))
            # Handle login error
            flash('Invalid Username or Password. Try Again...', 'error')
            return render_template('doctorlogin.html')
        except:
            # Handle login error
            flash('Invalid Username or Password. Try Again...', 'error')
            return render_template('doctorlogin.html')
    else:
        # This is a GET request, so render the login form
        return render_template('doctorlogin.html')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
