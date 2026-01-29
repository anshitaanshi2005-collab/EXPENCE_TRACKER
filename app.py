from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import json
import requests
import time
import os
from groq import Groq

_RATES_CACHE = {
    "timestamp": 0,
    "rates": {}
}

CACHE_TTL = 60 * 60  # 1 hour

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  

def get_db_connection():
    conn = sqlite3.connect('expenses.db')
    conn.row_factory = sqlite3.Row
    return conn

def _fetch_usd_rates():
    url = "https://api.exchangerate-api.com/v4/latest/USD"
    response = requests.get(url, timeout=5)
    data = response.json()

    if "rates" not in data:
        raise ValueError(f"Invalid API response: {data}")

    return data["rates"]

def get_usd_rate(currency):
    if currency == "USD":
        return 1.0

    now = time.time()

    # Refresh cache if expired
    if (
        not _RATES_CACHE["rates"]
        or now - _RATES_CACHE["timestamp"] > CACHE_TTL
    ):
        try:
            _RATES_CACHE["rates"] = _fetch_usd_rates()
            _RATES_CACHE["timestamp"] = now
        except Exception as e:
            print("Rate fetch error:", e)
            return 1.0  # safe fallback

    rates = _RATES_CACHE["rates"]

    if currency not in rates:
        # print(f"Unsupported currency: {currency}") # Suppressed to keep logs clean
        return 1.0

    return float(rates[currency])


def convert_to_usd(amount, currency):
    rate = get_usd_rate(currency)
    return round(amount / rate, 2)

def convert_from_usd(amount_usd, currency):
    rate = get_usd_rate(currency)
    return round(amount_usd * rate, 2)

# --- NEW HELPER: SPLITWISE DEBT ALGORITHM ---
def calculate_group_debts(group_id):
    """Calculates who owes whom, handling settlements/partial payments."""
    conn = get_db_connection()
    
    # 1. Get Members
    members = conn.execute(
        "SELECT user_id, username FROM group_members JOIN users ON users.id = group_members.user_id WHERE group_id = ?", 
        (group_id,)
    ).fetchall()
    
    user_map = {row['user_id']: row['username'] for row in members}
    balances = {row['user_id']: 0.0 for row in members}

    # 2. Calculate Balances
    expenses = conn.execute("SELECT * FROM group_expenses WHERE group_id = ?", (group_id,)).fetchall()
    
    for exp in expenses:
        # HANDLE SETTLEMENTS (The "Done Box" payments)
        if exp['description'] == 'Settlement':
            # In a settlement, the Payer (Debtor) is paying the Split User (Creditor)
            # We need to find who this payment was sent TO
            splits = conn.execute("SELECT user_id FROM expense_splits WHERE expense_id = ?", (exp['id'],)).fetchall()
            if splits:
                receiver_id = splits[0]['user_id']
                # Payer (Debtor) gave money, so their balance increases (becomes less negative)
                if exp['payer_id'] in balances:
                    balances[exp['payer_id']] += exp['amount']
                # Receiver (Creditor) got money, so their balance decreases (becomes less positive/owed)
                if receiver_id in balances:
                    balances[receiver_id] -= exp['amount']
        
        # HANDLE NORMAL EXPENSES
        else:
            # Payer gets credit (+)
            if exp['payer_id'] in balances:
                balances[exp['payer_id']] += exp['amount']
            
            # Splitters get debit (-)
            splits = conn.execute("SELECT user_id, amount_owed FROM expense_splits WHERE expense_id = ?", (exp['id'],)).fetchall()
            for split in splits:
                if split['user_id'] in balances:
                    balances[split['user_id']] -= split['amount_owed']

    conn.close()

    # 3. Minimize Transactions
    debtors = []
    creditors = []
    
    for uid, amount in balances.items():
        if amount < -0.01: debtors.append({'id': uid, 'amount': amount})
        if amount > 0.01: creditors.append({'id': uid, 'amount': amount})

    debtors.sort(key=lambda x: x['amount'])
    creditors.sort(key=lambda x: x['amount'], reverse=True)

    transactions = []
    d_idx = 0
    c_idx = 0

    while d_idx < len(debtors) and c_idx < len(creditors):
        debtor = debtors[d_idx]
        creditor = creditors[c_idx]

        amount = min(abs(debtor['amount']), creditor['amount'])
        
        transactions.append({
            'from_id': debtor['id'],
            'to_id': creditor['id'],
            'from': user_map.get(debtor['id'], 'Unknown'),
            'to': user_map.get(creditor['id'], 'Unknown'),
            'amount': round(amount, 2)
        })

        debtor['amount'] += amount
        creditor['amount'] -= amount

        if abs(debtor['amount']) < 0.01: d_idx += 1
        if creditor['amount'] < 0.01: c_idx += 1

    return transactions


def init_db():
    conn = get_db_connection()

    # --- ORIGINAL TABLES ---
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
                currency TEXT NOT NULL DEFAULT 'USD',
        amount_usd REAL NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            amount REAL NOT NULL,
               currency TEXT NOT NULL DEFAULT 'USD',
        amount_usd REAL NOT NULL,
            period TEXT NOT NULL DEFAULT 'monthly',
            start_date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.execute(
       'CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, date)'
    )
    conn.execute(
      'CREATE INDEX IF NOT EXISTS idx_expenses_user_category ON expenses(user_id, category)'
    )
    conn.execute(
    'CREATE INDEX IF NOT EXISTS idx_budgets_user ON budgets(user_id)'
    )

    # --- NEW SPLITWISE TABLES ---
    conn.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at TEXT NOT NULL,
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            PRIMARY KEY (group_id, user_id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS group_expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            payer_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            description TEXT NOT NULL,
            date TEXT NOT NULL,
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (payer_id) REFERENCES users (id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS expense_splits (
            expense_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            amount_owed REAL NOT NULL,
            FOREIGN KEY (expense_id) REFERENCES group_expenses (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

# Routes
@app.route('/set_currency', methods=['POST'])
def set_currency():
    currency = request.form.get('currency')
    if currency:
        session['currency'] = currency
    return redirect(url_for('dashboard'))

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        
        try:
            hashed_password = generate_password_hash(password)
            conn.execute(
                'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                (username, email, hashed_password)
            )
            conn.commit()
            flash('Account created successfully! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists!')
        finally:
            conn.close()
    
    return render_template('signup.html')

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
            session['username'] = user['username']
            flash('Logged in successfully!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    display_currency = session.get('currency', 'INR')

    # ================= TOTAL EXPENSES =================
    total_expenses_usd = conn.execute(
        'SELECT COALESCE(SUM(amount_usd), 0) FROM expenses WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()[0]

    total_expenses = convert_from_usd(total_expenses_usd, display_currency)

    # ================= MONTHLY EXPENSES =================
    current_month_start = datetime.now().replace(day=1).strftime('%Y-%m-%d')

    monthly_expenses_usd = conn.execute(
        'SELECT COALESCE(SUM(amount_usd), 0) FROM expenses WHERE user_id = ? AND date >= ?',
        (session['user_id'], current_month_start)
    ).fetchone()[0]

    monthly_expenses = convert_from_usd(monthly_expenses_usd, display_currency)

    # ================= RECENT EXPENSES =================
    rows = conn.execute('''
        SELECT * FROM expenses
        WHERE user_id = ?
        ORDER BY date DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()

    recent_expenses = []
    for row in rows:
        exp = dict(row)
        exp['amount_display'] = convert_from_usd(
            exp['amount_usd'], display_currency
        )
        recent_expenses.append(exp)

    # ================= BUDGETS =================
    budgets = conn.execute(
        'SELECT * FROM budgets WHERE user_id = ?',
        (session['user_id'],)
    ).fetchall()

    total_budget_usd = 0
    total_budget_spent_usd = 0
    budget_alerts = []

    for budget in budgets:
        budget_amount_usd = float(budget['amount_usd'])
        total_budget_usd += budget_amount_usd

        # Period dates
        if budget['period'] == 'monthly':
            start_date = datetime.now().replace(day=1).strftime('%Y-%m-%d')
        elif budget['period'] == 'weekly':
            start_date = (datetime.now() - timedelta(days=datetime.now().weekday())).strftime('%Y-%m-%d')
        else:  # yearly
            start_date = datetime.now().replace(month=1, day=1).strftime('%Y-%m-%d')

        end_date = datetime.now().strftime('%Y-%m-%d')

        actual_spending_usd = conn.execute(
            '''
            SELECT COALESCE(SUM(amount_usd), 0) FROM expenses
            WHERE user_id = ? AND category = ? AND date BETWEEN ? AND ?
            ''',
            (session['user_id'], budget['category'], start_date, end_date)
        ).fetchone()[0]

        total_budget_spent_usd += actual_spending_usd

        percentage_used = (
            actual_spending_usd / budget_amount_usd * 100
            if budget_amount_usd > 0 else 0
        )

        remaining_usd = budget_amount_usd - actual_spending_usd

        if percentage_used >= 80:
            budget_alerts.append({
                'category': budget['category'],
                'status': 'exceeded' if percentage_used >= 100 else 'warning',
                'percentage': round(percentage_used, 1),
                'remaining': convert_from_usd(remaining_usd, display_currency)
            })

    conn.close()

    total_budget = convert_from_usd(total_budget_usd, display_currency)
    total_budget_spent = convert_from_usd(total_budget_spent_usd, display_currency)

    return render_template(
        'dashboard.html',
        total_expenses=total_expenses,
        monthly_expenses=monthly_expenses,
        total_budget=total_budget,
        total_budget_spent=total_budget_spent,
        
       
        recent_expenses=recent_expenses,
        
        
        budget_alerts=budget_alerts,
        currency=display_currency
    )


@app.route('/expenses')
def expenses():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    expenses_list = conn.execute('''
        SELECT * FROM expenses 
        WHERE user_id = ? 
        ORDER BY date DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('expenses.html', expenses=expenses_list)

@app.route('/add_expense', methods=['GET', 'POST'])
def add_expense():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        category = request.form['category']
        currency = request.form['currency']
        description = request.form['description']
        date = request.form['date'] or datetime.now().strftime('%Y-%m-%d')

        amount_usd = convert_to_usd(amount, currency)

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO expenses (user_id, amount,currency,amount_usd, category, description, date) VALUES (?, ?, ?, ?, ?,?,?)',
            (session['user_id'], amount,currency,amount_usd, category, description, date)
        )
        conn.commit()
        conn.close()
        
        flash('Expense added successfully!')
        return redirect(url_for('expenses'))
    
    return render_template('add_expense.html')

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
def edit_expense(expense_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    if request.method == 'POST':
        amount = float(request.form['amount'])
        currency = request.form.get('currency')
        category = request.form['category']
        description = request.form['description']
        date = request.form['date'] or datetime.now().strftime('%Y-%m-%d')

       
        amount_usd = convert_to_usd(amount, currency)


        conn.execute(
            '''
            UPDATE expenses
            SET amount = ?, currency = ?, amount_usd = ?, category = ?, description = ?, date = ?
            WHERE id = ? AND user_id = ?
            ''',
            (amount, currency, amount_usd, category, description, date, expense_id, session['user_id'])
        )

        conn.commit()
        conn.close()

        flash('Expense updated successfully!')
        return redirect(url_for('expenses'))

    # ================= GET =================
    expense = conn.execute(
        'SELECT * FROM expenses WHERE id = ? AND user_id = ?',
        (expense_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not expense:
        flash('Expense not found!')
        return redirect(url_for('expenses'))

    return render_template(
        'edit_expense.html',
        expense=expense,
        selected_currency=expense['currency']  
    )


@app.route('/delete_expense/<int:expense_id>')
def delete_expense(expense_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute(
        'DELETE FROM expenses WHERE id = ? AND user_id = ?',
        (expense_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    
    flash('Expense deleted successfully!')
    return redirect(url_for('expenses'))
@app.route('/analytics')
def analytics():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    display_currency = session.get('currency', 'INR')

    # ================= DAILY SPENDING (LAST 7 DAYS) =================
    end_date = datetime.now()
    start_date = end_date - timedelta(days=6)

    daily_data = []
    labels = []

    for i in range(7):
        current_date = (start_date + timedelta(days=i)).strftime('%Y-%m-%d')
        labels.append((start_date + timedelta(days=i)).strftime('%b %d'))

        total_usd = conn.execute(
            '''
            SELECT COALESCE(SUM(amount_usd), 0)
            FROM expenses
            WHERE user_id = ? AND date = ?
            ''',
            (session['user_id'], current_date)
        ).fetchone()[0]

        daily_data.append(
            convert_from_usd(total_usd, display_currency)
        )

    
    categories_data = conn.execute(
        '''
        SELECT category, COALESCE(SUM(amount_usd), 0) AS total_usd
        FROM expenses
        WHERE user_id = ?
        GROUP BY category
        ''',
        (session['user_id'],)
    ).fetchall()

    category_labels = [row['category'] for row in categories_data]
    category_totals = [
        convert_from_usd(row['total_usd'], display_currency)
        for row in categories_data
    ]

    conn.close()

    return render_template(
        'analytics.html',
        labels=json.dumps(labels),
        daily_data=json.dumps(daily_data),
        category_labels=json.dumps(category_labels),
        category_totals=json.dumps(category_totals),
        currency=display_currency
    )




@app.route('/budgets')
def budgets():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    display_currency = session.get('currency', 'INR')

    budgets_list = conn.execute(
        'SELECT * FROM budgets WHERE user_id = ? ORDER BY category',
        (session['user_id'],)
    ).fetchall()

    budgets_with_spending = []

    for budget in budgets_list:
        budget_dict = dict(budget)

        budget_amount_usd = float(budget['amount_usd'])

        # Period dates
        if budget['period'] == 'monthly':
            start_date = datetime.now().replace(day=1).strftime('%Y-%m-%d')
        elif budget['period'] == 'weekly':
            start_date = (
                datetime.now() - timedelta(days=datetime.now().weekday())
            ).strftime('%Y-%m-%d')
        else:  # yearly
            start_date = datetime.now().replace(month=1, day=1).strftime('%Y-%m-%d')

        end_date = datetime.now().strftime('%Y-%m-%d')

        actual_spending_usd = conn.execute(
            '''
            SELECT COALESCE(SUM(amount_usd), 0)
            FROM expenses
            WHERE user_id = ? AND category = ? AND date BETWEEN ? AND ?
            ''',
            (session['user_id'], budget['category'], start_date, end_date)
        ).fetchone()[0]

        remaining_usd = budget_amount_usd - actual_spending_usd

        percentage_used = (
            actual_spending_usd / budget_amount_usd * 100
            if budget_amount_usd > 0 else 0
        )

        # Convert values for display (use conversion functions directly)
        budget_dict['actual_spending'] = convert_from_usd(
            actual_spending_usd, display_currency
        )
        budget_dict['remaining'] = convert_from_usd(
            remaining_usd, display_currency
        )
        budget_dict['amount'] = convert_from_usd(
            budget_amount_usd, display_currency
        )
        budget_dict['percentage_used'] = round(percentage_used, 1)

        budgets_with_spending.append(budget_dict)

    conn.close()

    return render_template(
        'budgets.html',
        budgets=budgets_with_spending,
        currency=display_currency
    )



@app.route('/add_budget', methods=['GET', 'POST'])
def add_budget():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        category = request.form['category']
        amount = float(request.form['amount'])
        currency = request.form['currency']
        period = request.form['period']
        start_date = request.form['start_date'] or datetime.now().strftime('%Y-%m-%d')

        amount_usd = convert_to_usd(amount, currency)

        conn = get_db_connection()

        existing = conn.execute(
            '''
            SELECT * FROM budgets
            WHERE user_id = ? AND category = ? AND period = ?
            ''',
            (session['user_id'], category, period)
        ).fetchone()

        if existing:
            flash('Budget already exists for this category and period!')
            conn.close()
            return render_template('add_budget.html')

        conn.execute(
            '''
            INSERT INTO budgets
            (user_id, category, amount, currency, amount_usd, period, start_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (session['user_id'], category, amount, currency, amount_usd, period, start_date)
        )

        conn.commit()
        conn.close()

        flash('Budget added successfully!')
        return redirect(url_for('budgets'))

    return render_template('add_budget.html')


@app.route('/edit_budget/<int:budget_id>', methods=['GET', 'POST'])
def edit_budget(budget_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    
    if request.method == 'POST':
        amount = float(request.form['amount'])
        currency = request.form.get('currency')
        period = request.form['period']
        start_date = request.form['start_date'] or datetime.now().strftime('%Y-%m-%d')

        amount_usd = convert_to_usd(amount, currency)

        conn.execute(
            '''
            UPDATE budgets
            SET amount = ?, currency = ?, amount_usd = ?, period = ?, start_date = ?
            WHERE id = ? AND user_id = ?
            ''',
            (amount, currency, amount_usd, period, start_date, budget_id, session['user_id'])
        )
        conn.commit()
        conn.close()

        flash('Budget updated successfully!')
        return redirect(url_for('budgets'))

    # =============== GET ===============
    budget = conn.execute(
        'SELECT * FROM budgets WHERE id = ? AND user_id = ?',
        (budget_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not budget:
        flash('Budget not found!')
        return redirect(url_for('budgets'))

    return render_template(
        'edit_budget.html',
        budget=budget,
        selected_currency=budget['currency']  
    )


@app.route('/delete_budget/<int:budget_id>')
def delete_budget(budget_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute(
        'DELETE FROM budgets WHERE id = ? AND user_id = ?',
        (budget_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    
    flash('Budget deleted successfully!')
    return redirect(url_for('budgets'))

# ================= NEW: SPLITWISE FEATURES =================

@app.route('/groups')
def groups():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    user_groups = conn.execute('''
        SELECT g.id, g.name, COUNT(m.user_id) as member_count 
        FROM groups g
        JOIN group_members m ON g.id = m.group_id
        WHERE m.user_id = ?
        GROUP BY g.id
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('groups.html', groups=user_groups)

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'user_id' not in session: return redirect(url_for('login'))
    group_name = request.form['name']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO groups (name, created_by, created_at) VALUES (?, ?, ?)',
                   (group_name, session['user_id'], datetime.now()))
    group_id = cursor.lastrowid
    
    # Add creator as first member
    cursor.execute('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)',
                   (group_id, session['user_id'], datetime.now()))
    conn.commit()
    conn.close()
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/group/<int:group_id>')
def group_detail(group_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    
    # Access Control
    is_member = conn.execute('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', 
                             (group_id, session['user_id'])).fetchone()
    if not is_member:
        conn.close()
        flash("You are not a member of this group.")
        return redirect(url_for('groups'))

    group = conn.execute('SELECT * FROM groups WHERE id = ?', (group_id,)).fetchone()
    
    # Get Expenses
    expenses = conn.execute('''
        SELECT ge.*, u.username as payer_name 
        FROM group_expenses ge 
        JOIN users u ON ge.payer_id = u.id 
        WHERE group_id = ? ORDER BY date DESC
    ''', (group_id,)).fetchall()
    
    # Get Members (For 'Paid By' list)
    members = conn.execute('''
        SELECT u.id, u.username, u.email 
        FROM group_members gm 
        JOIN users u ON gm.user_id = u.id 
        WHERE group_id = ?
    ''', (group_id,)).fetchall()
    
    conn.close()
    
    debts = calculate_group_debts(group_id)
    return render_template('group_detail.html', group=group, expenses=expenses, members=members, debts=debts)

@app.route('/group/<int:group_id>/add_member', methods=['POST'])
def add_member(group_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    username = request.form['username']
    conn = get_db_connection()
    
    # NEW LOGIC: Check by username. If not exists, CREATE IT.
    user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    
    if not user:
        # Create "Ghost" user automatically so we can add them to the bill
        # Using a timestamp to ensure unique email
        dummy_email = f"{username}_{int(time.time())}@placeholder.com"
        dummy_pass = generate_password_hash("placeholder") # They can't login, which is fine
        c = conn.cursor()
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, dummy_email, dummy_pass))
        user_id = c.lastrowid
        conn.commit()
        flash(f'Created new user "{username}" and added to group!')
    else:
        user_id = user['id']
        flash(f'Added "{username}" to group!')

    # Add to group
    try:
        conn.execute('INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)',
                     (group_id, user_id, datetime.now()))
        conn.commit()
    except sqlite3.IntegrityError:
        flash('User already in group.')
    
    conn.close()
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/group/<int:group_id>/add_expense', methods=['POST'])
def add_group_expense(group_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    amount = float(request.form['amount'])
    desc = request.form['description']
    payer_id = int(request.form['payer_id']) # Now we use the ID from the dropdown
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Insert Expense
    cursor.execute('INSERT INTO group_expenses (group_id, payer_id, amount, description, date) VALUES (?, ?, ?, ?, ?)', 
                   (group_id, payer_id, amount, desc, datetime.now()))
    expense_id = cursor.lastrowid
    
    # Split equally among ALL members
    members = conn.execute('SELECT user_id FROM group_members WHERE group_id = ?', (group_id,)).fetchall()
    if members:
        split = amount / len(members)
        for m in members:
            conn.execute('INSERT INTO expense_splits (expense_id, user_id, amount_owed) VALUES (?, ?, ?)',
                         (expense_id, m['user_id'], split))
        conn.commit()
    conn.close()
    return redirect(url_for('group_detail', group_id=group_id))

@app.route('/group/<int:group_id>/settle_up', methods=['POST'])
def settle_up(group_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    payer_id = int(request.form['from_id']) # Debtor
    receiver_id = int(request.form['to_id']) # Creditor
    amount = float(request.form['amount']) # Partial or Full amount
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Record Settlement as an Expense (Payer = Debtor)
    c.execute('INSERT INTO group_expenses (group_id, payer_id, amount, description, date) VALUES (?, ?, ?, ?, ?)',
              (group_id, payer_id, amount, "Settlement", datetime.now()))
    exp_id = c.lastrowid
    
    # Assign the split fully to the Receiver (Creditor)
    # Math: Debtor Paid (+balance), Creditor Received (-balance)
    c.execute('INSERT INTO expense_splits (expense_id, user_id, amount_owed) VALUES (?, ?, ?)',
              (exp_id, receiver_id, amount))
    
    conn.commit()
    conn.close()
    flash('Payment recorded!')
    return redirect(url_for('group_detail', group_id=group_id))

# ================= CHATBOT =================

groq_client = Groq(
    api_key="YOUR GROQ API"
)

def get_user_financial_context(user_id):
    conn = get_db_connection()

    # Total expenses
    total_usd = conn.execute(
        "SELECT COALESCE(SUM(amount_usd), 0) FROM expenses WHERE user_id = ?",
        (user_id,)
    ).fetchone()[0]

    # Monthly expenses
    month_start = datetime.now().replace(day=1).strftime('%Y-%m-%d')
    monthly_usd = conn.execute(
        """
        SELECT COALESCE(SUM(amount_usd), 0)
        FROM expenses WHERE user_id = ? AND date >= ?
        """,
        (user_id, month_start)
    ).fetchone()[0]

    # Category breakdown
    categories = conn.execute(
        """
        SELECT category, SUM(amount_usd) as total
        FROM expenses
        WHERE user_id = ?
        GROUP BY category
        """,
        (user_id,)
    ).fetchall()

    # Budgets
    budgets = conn.execute(
        """
        SELECT category, amount_usd
        FROM budgets
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchall()

    conn.close()

    return {
        "total_expenses_usd": round(total_usd, 2),
        "monthly_expenses_usd": round(monthly_usd, 2),
        "categories": {row["category"]: round(row["total"], 2) for row in categories},
        "budgets": {row["category"]: round(row["amount_usd"], 2) for row in budgets},
    }
@app.route('/chatbot', methods=['POST'])
def chatbot():
    if 'user_id' not in session:
        return {"reply": "Unauthorized"}, 401

    data = request.get_json()
    user_message = data.get("message", "").strip()

    if not user_message:
        return {"reply": "Please enter a message."}

    context = get_user_financial_context(session['user_id'])

    system_prompt = f"""
You are a personal finance assistant.

User data (USD):
- Total expenses: {context['total_expenses_usd']}
- Monthly expenses: {context['monthly_expenses_usd']}
- Category totals: {context['categories']}
- Budgets: {context['budgets']}

Rules:
- Do not invent data
- Answer clearly
"""

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            temperature=0.4,
            max_tokens=300
        )


        return {"reply": response.choices[0].message.content}

    except Exception as e:
        print(e)
        return {"reply": "AI service error. Try again later."}


if __name__ == '__main__':
    init_db()
    try:
        _RATES_CACHE["rates"] = _fetch_usd_rates()
        _RATES_CACHE["timestamp"] = time.time()
    except Exception:
        pass
    app.run(debug=True)