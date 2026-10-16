# Connected Care Website

## Current status

The public homepage, patient records view, doctor workspace and hospital-administration view are frontend pages. Secure sign-in, backend storage, patient consent, doctor verification, QR access, medical-record sharing and prescription saving are not connected yet.

The patient, doctor, history and administration pages intentionally show empty states. No patient, doctor, visit or prescription examples should be added until real backend-backed records exist.

## Preview

Double-click `start-website.bat` to start the site on `http://127.0.0.1:8000`. Keep the server window open while browsing; close it to stop the local server.

## Important security limitation

Do not enter or upload real medical information. Patient records and PDFs cannot currently be securely saved or shared. The visible service-status notices should remain until authentication, secure file storage, authorization, consent and audit logging are connected and tested.
