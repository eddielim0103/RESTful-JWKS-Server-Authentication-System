# CSCE 3550 Project 1 - JWKS Server
Student Information
Name: Eddie Lim

Student ID: CL1016

Class: CSCE 3550

University: University of North Texas

Project Overview
This project is a RESTful JWKS (JSON Web Key Set) server implemented using FastAPI and Python. It provides endpoints to serve public RSA keys and issue signed JWTs. It handles key expiration and supports issuing expired tokens for testing purposes through query parameters.

Prerequisites
Python 3.13+

Virtual environment (venv)

Setup and Installation
Create a virtual environment:

PowerShell
python -m venv venv
Activate the virtual environment:

Windows: .\venv\Scripts\activate

Mac/Linux: source venv/bin/activate

Install required dependencies:

PowerShell
pip install fastapi uvicorn python-jose[cryptography] cryptography pytest pytest-cov httpx
How to Run the Server
Ensure the virtual environment is activated.

Run the server using the following command:

PowerShell
python main.py
The server will start at http://127.0.0.1:8080.

How to Run Tests
To verify the functionality and check test coverage (which is maintained at 95%), run:

PowerShell
pytest --cov=main .
API Endpoints
GET /jwks: Serves all unexpired public keys in JWKS format.

POST /auth: Returns a signed JWT.

Use query parameter ?expired=true to receive a token signed with an expired key.

GET /.well-known/jwks.json: Standardized path for JWKS discovery.
