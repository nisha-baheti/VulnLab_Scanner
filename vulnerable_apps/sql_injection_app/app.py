from flask import Flask, request

app = Flask(__name__)

# Fake database
users = {
    "admin": "1234",
    "user": "pass"
}

@app.route('/')
def home():
    return '''
    <h2>Login Page</h2>
    <form action="/login">
        Username: <input name="username"><br>
        Password: <input name="password"><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/login')
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    # ❌ INTENTIONALLY VULNERABLE (simulating SQL query)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print("Executing Query:", query)

    # Simulating SQL behavior
    if "'" in username or "'" in password:
        return "SQL Error: You have an error in your SQL syntax"

    if username in users and users[username] == password:
        return "Login Successful!"
    else:
        return "Invalid Credentials"

if __name__ == "__main__":
    app.run(debug=True)