# 💳 Expense Tracker Application

**Take control of your finances.** This comprehensive Expense Tracker application allows users to log daily spending, categorize expenses, and visualize financial habits through dynamic, interactive charts. Built with security and scalability in mind using Flask and SQLite.

---

## 📖 Table of Contents
- [✨ Key Features](#-key-features)
- [📸 Application Preview](#-application-preview)
- [🛠️ Tech Stack](#-tech-stack)
- [💾 Database Schema](#-database-schema)
- [🔌 API Routes](#-api-routes)
- [⚙️ Installation & Setup](#-installation--setup)
- [🔮 Future Roadmap](#-future-roadmap)
- [🤝 Contributing](#-contributing)

---

## ✨ Key Features

* **🔐 Secure Authentication**: 
    * User registration and login system.
    * Passwords are hashed using `werkzeug.security` before storage.
    * Session-based authentication protects private routes.
* **📊 Interactive Dashboard**: 
    * At-a-glance view of total spending.
    * "Recent Expenses" table for quick review.
* **📈 Visual Analytics**: 
    * **Trend Line**: Visualize spending over the last 7 days.
    * **Doughnut Chart**: Breakdown of expenses by category (Food, Transport, Bills, etc.).
* **📝 Full Expense Management**: 
    * **Create**: Add new expenses with amount, category, date, and description.
    * **Read**: View full expense history.
    * **Update**: Edit details of existing expenses.
    * **Delete**: Remove erroneous entries.
* **📱 Responsive Interface**: Clean, minimal UI built with HTML5 and CSS3.

---

## 📸 Application Preview

| **Dashboard** | **Analytics** |
|:---:|:---:|
| ![Dashboard](./assets/dashboard.png) | ![Analytics](./assets/analytics.png) |
| *Real-time financial overview* | *Interactive spending breakdown* |

| **Expense Management** | **Secure Login** |
|:---:|:---:|
| ![Expenses](./assets/expenses.png) | ![Login](./assets/login.png) |
| *CRUD operations for expenses* | *Secure user authentication* |

---

## 🛠️ Tech Stack

### Backend
* **Framework**: Flask (Python)
* **Database**: SQLite3
* **Authentication**: Werkzeug Security (Hash/Salt)

### Frontend
* **Templating**: Jinja2
* **Styling**: CSS3 (Custom responsive design)
* **Scripting**: JavaScript (ES6)
* **Charts**: Chart.js library for data visualization

---

## 💾 Database Schema

The application uses **SQLite** with two primary tables connected by a foreign key relationship.

### 1. `users` Table
Stores user account credentials.
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER | Primary Key, Auto-increment |
| `username` | TEXT | Unique username |
| `email` | TEXT | Unique email address |
| `password` | TEXT | Hashed password string |

### 2. `expenses` Table
Stores individual expense records linked to a user.
| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER | Primary Key, Auto-increment |
| `user_id` | INTEGER | Foreign Key (Links to `users.id`) |
| `amount` | REAL | Cost of the expense |
| `category` | TEXT | Category (e.g., Food, Travel) |
| `description`| TEXT | Optional details |
| `date` | TEXT | Date of expense (YYYY-MM-DD) |

---

## 🔌 API Routes

| Method | Endpoint | Description | Access |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Landing page / Redirect to dashboard | Public |
| `POST` | `/signup` | Register a new user account | Public |
| `POST` | `/login` | Authenticate user and start session | Public |
| `GET` | `/logout` | Clear session and logout | Private |
| `GET` | `/dashboard`| Main user dashboard with summary | Private |
| `POST` | `/add_expense`| Submit a new expense entry | Private |
| `GET` | `/expenses` | View all expense history | Private |
| `GET` | `/analytics` | Get JSON data for charts | Private |

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/anshitaanshi2005-collab/EXPENCE_TRACKER.git](https://github.com/anshitaanshi2005-collab/EXPENCE_TRACKER.git)
cd EXPENCE_TRACKER
```

### 2. Create Virtual Environment
Isolate dependencies to prevent conflicts.
```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```
### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
The database will automatically initialize on the first run.
```bash
python app.py
```

### 5. Access

Open http://127.0.0.1:5000 in your browser.

---

## 🔮 Future Roadmap

- Export Data: Ability to download expenses as CSV/PDF.

- Budget Goals: Set monthly limits per category.

- Dark Mode: Toggle between light and dark themes.

- Profile Management: Allow users to update passwords/email.

---

## 🤝 Contributing

- Fork the repository.

- Create a feature branch (git checkout -b feature/NewFeature).

- Commit your changes (git commit -m "Add NewFeature").

- Push to the branch (git push origin feature/NewFeature).

- Open a Pull Request.

---

## 📄 License

Distributed under the MIT License. See LICENSE for more information.

---

## ✉️ Contact

Mail : anshitaanshi2005@gmail.com

---