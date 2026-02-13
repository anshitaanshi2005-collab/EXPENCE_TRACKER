# Code Citations

## License: unknown
https://github.com/rmit-s3514164-Peng-Fu/music-threapy/blob/d70a85b8d4acc08824f43075198531e612a24356/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: GPL-3.0
https://github.com/Strikor/HCIProject/blob/b26830ebadfb0f1f0e0d9c20557523be71132ced/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: unknown
https://github.com/MaximilianLipkevich/Project/blob/e968d0eb8744123c929cf54a5a9367c1e109f7c2/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: unknown
https://github.com/Ooshy/PythonChecker/blob/e7c83cc756f2499ba29c57aa5103b099469e7748/server.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: unknown
https://github.com/ziminl/flask-twitter-clone/blob/088bd9dc546a96798b3eb642d09f2339699024b4/flask.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: unknown
https://github.com/nakasan0903/nakayama/blob/c486c7d712d0da31a02a6509d95130bb8b106918/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: unknown
https://github.com/catalina2001/TICKETHUB-COLLAO-MAGGI/blob/4543140131cba04448ce1a412a87b6b710ce1d0f/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: MIT
https://github.com/rikurampanen/python-testing/blob/3f3a0df0dd4be7307b4a0ce1da5e10beb2c052fc/flask/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session[
```


## License: unknown
https://github.com/Ooshy/PythonChecker/blob/e7c83cc756f2499ba29c57aa5103b099469e7748/server.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/rmit-s3514164-Peng-Fu/music-threapy/blob/d70a85b8d4acc08824f43075198531e612a24356/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/nakasan0903/nakayama/blob/c486c7d712d0da31a02a6509d95130bb8b106918/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: MIT
https://github.com/rikurampanen/python-testing/blob/3f3a0df0dd4be7307b4a0ce1da5e10beb2c052fc/flask/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/ziminl/flask-twitter-clone/blob/088bd9dc546a96798b3eb642d09f2339699024b4/flask.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/catalina2001/TICKETHUB-COLLAO-MAGGI/blob/4543140131cba04448ce1a412a87b6b710ce1d0f/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: GPL-3.0
https://github.com/Strikor/HCIProject/blob/b26830ebadfb0f1f0e0d9c20557523be71132ced/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/MaximilianLipkevich/Project/blob/e968d0eb8744123c929cf54a5a9367c1e109f7c2/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/nakasan0903/nakayama/blob/c486c7d712d0da31a02a6509d95130bb8b106918/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: GPL-3.0
https://github.com/Strikor/HCIProject/blob/b26830ebadfb0f1f0e0d9c20557523be71132ced/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: MIT
https://github.com/rikurampanen/python-testing/blob/3f3a0df0dd4be7307b4a0ce1da5e10beb2c052fc/flask/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/rmit-s3514164-Peng-Fu/music-threapy/blob/d70a85b8d4acc08824f43075198531e612a24356/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/catalina2001/TICKETHUB-COLLAO-MAGGI/blob/4543140131cba04448ce1a412a87b6b710ce1d0f/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/MaximilianLipkevich/Project/blob/e968d0eb8744123c929cf54a5a9367c1e109f7c2/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/Ooshy/PythonChecker/blob/e7c83cc756f2499ba29c57aa5103b099469e7748/server.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/ziminl/flask-twitter-clone/blob/088bd9dc546a96798b3eb642d09f2339699024b4/flask.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/MaximilianLipkevich/Project/blob/e968d0eb8744123c929cf54a5a9367c1e109f7c2/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: unknown
https://github.com/Ooshy/PythonChecker/blob/e7c83cc756f2499ba29c57aa5103b099469e7748/server.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: unknown
https://github.com/rmit-s3514164-Peng-Fu/music-threapy/blob/d70a85b8d4acc08824f43075198531e612a24356/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: unknown
https://github.com/ziminl/flask-twitter-clone/blob/088bd9dc546a96798b3eb642d09f2339699024b4/flask.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: unknown
https://github.com/nakasan0903/nakayama/blob/c486c7d712d0da31a02a6509d95130bb8b106918/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: unknown
https://github.com/catalina2001/TICKETHUB-COLLAO-MAGGI/blob/4543140131cba04448ce1a412a87b6b710ce1d0f/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: GPL-3.0
https://github.com/Strikor/HCIProject/blob/b26830ebadfb0f1f0e0d9c20557523be71132ced/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: MIT
https://github.com/rikurampanen/python-testing/blob/3f3a0df0dd4be7307b4a0ce1da5e10beb2c052fc/flask/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            
```


## License: unknown
https://github.com/nakasan0903/nakayama/blob/c486c7d712d0da31a02a6509d95130bb8b106918/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: unknown
https://github.com/catalina2001/TICKETHUB-COLLAO-MAGGI/blob/4543140131cba04448ce1a412a87b6b710ce1d0f/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: GPL-3.0
https://github.com/Strikor/HCIProject/blob/b26830ebadfb0f1f0e0d9c20557523be71132ced/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: MIT
https://github.com/rikurampanen/python-testing/blob/3f3a0df0dd4be7307b4a0ce1da5e10beb2c052fc/flask/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: unknown
https://github.com/MaximilianLipkevich/Project/blob/e968d0eb8744123c929cf54a5a9367c1e109f7c2/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: unknown
https://github.com/Ooshy/PythonChecker/blob/e7c83cc756f2499ba29c57aa5103b099469e7748/server.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: unknown
https://github.com/rmit-s3514164-Peng-Fu/music-threapy/blob/d70a85b8d4acc08824f43075198531e612a24356/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: unknown
https://github.com/ziminl/flask-twitter-clone/blob/088bd9dc546a96798b3eb642d09f2339699024b4/flask.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user
```


## License: unknown
https://github.com/nakasan0903/nakayama/blob/c486c7d712d0da31a02a6509d95130bb8b106918/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: unknown
https://github.com/catalina2001/TICKETHUB-COLLAO-MAGGI/blob/4543140131cba04448ce1a412a87b6b710ce1d0f/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: GPL-3.0
https://github.com/Strikor/HCIProject/blob/b26830ebadfb0f1f0e0d9c20557523be71132ced/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: MIT
https://github.com/rikurampanen/python-testing/blob/3f3a0df0dd4be7307b4a0ce1da5e10beb2c052fc/flask/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: unknown
https://github.com/MaximilianLipkevich/Project/blob/e968d0eb8744123c929cf54a5a9367c1e109f7c2/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: unknown
https://github.com/Ooshy/PythonChecker/blob/e7c83cc756f2499ba29c57aa5103b099469e7748/server.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: unknown
https://github.com/rmit-s3514164-Peng-Fu/music-threapy/blob/d70a85b8d4acc08824f43075198531e612a24356/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: unknown
https://github.com/ziminl/flask-twitter-clone/blob/088bd9dc546a96798b3eb642d09f2339699024b4/flask.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username
```


## License: unknown
https://github.com/ziminl/flask-twitter-clone/blob/088bd9dc546a96798b3eb642d09f2339699024b4/flask.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/nakasan0903/nakayama/blob/c486c7d712d0da31a02a6509d95130bb8b106918/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/catalina2001/TICKETHUB-COLLAO-MAGGI/blob/4543140131cba04448ce1a412a87b6b710ce1d0f/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: GPL-3.0
https://github.com/Strikor/HCIProject/blob/b26830ebadfb0f1f0e0d9c20557523be71132ced/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: MIT
https://github.com/rikurampanen/python-testing/blob/3f3a0df0dd4be7307b4a0ce1da5e10beb2c052fc/flask/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/MaximilianLipkevich/Project/blob/e968d0eb8744123c929cf54a5a9367c1e109f7c2/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/Ooshy/PythonChecker/blob/e7c83cc756f2499ba29c57aa5103b099469e7748/server.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```


## License: unknown
https://github.com/rmit-s3514164-Peng-Fu/music-threapy/blob/d70a85b8d4acc08824f43075198531e612a24356/app.py

```
signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username
```

