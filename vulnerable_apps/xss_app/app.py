from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <h2>Search Page</h2>
    <form action="/search">
        Enter search: <input name="q">
        <input type="submit" value="Search">
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get("q")

    # ❌ Vulnerable: directly reflecting user input
    return f"<h3>Results for: {query}</h3>"

if __name__ == "__main__":
    app.run(debug=True)