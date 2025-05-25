# Shipping Management App

## Overview
This is a Flask-based web application for managing shipments and users. It allows users to track shipments and view history, while admins manage shipments and user accounts. The app features a modern, responsive UI with advanced search filters and a SQLite backend.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/galyfilsaime/shipping-management-app.git
   cd shipping-management-app
   ```
2. Create a virtual environment and activate it:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   source venv/bin/activate  # macOS/Linux
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set environment variables (optional):
   ```bash
   setx JWT_SECRET_KEY "your-static-jwt-secret-key-12345"  # Windows
   export JWT_SECRET_KEY="your-static-jwt-secret-key-12345"  # macOS/Linux
   ```
5. Run the app:
   ```bash
   python app.py
   ```
6. Access the app at `http://localhost:5000`.

## Usage
The Shipping Management App provides a user-friendly interface for managing shipments and users, with distinct functionalities for users and admins. Below is an overview of how to use the app:

### General Features
- **Navigation Bar**: Styled with modern icons, the navbar adapts to login status:
  - **Not Logged In**: Shows "Home" (house icon), "Track" (search icon), and "Account" (user icon) with dropdown for "Login" (sign-in icon) and "Register" (user-plus icon).
  - **User Logged In**: Shows "Home," "Track," and "Account" with dropdown for "Dashboard" (tachometer icon, user dashboard) and "Logout" (sign-out icon).
  - **Admin Logged In**: Shows "Dashboard" (shield icon, admin dashboard) and "Logout" (sign-out icon).
- **Home Page**: Access at `http://localhost:5000` for the welcome page with navigation links.
- **Registration**: Create a user account at `/register` with username, email, and password. Users get the "user" role.
- **Login**: Log in at `/login` with username/email and password. An admin account (`admin`, `admin123`) is created on first run.
- **Logout**: Log out at `/logout` to end the session, clearing authentication cookies and redirecting to the home page.
- **Shipment Tracking**: Use `/track` to search for a shipment by tracking number (no login required). Displays shipment details if found.
- **Responsive Design**: Features cards, gradients, Poppins font, and Font Awesome icons, optimized for desktop and mobile (e.g., 375x667px).

### User Features
- **Dashboard** (`/dashboard`): Users access their dashboard to:
  - View assigned shipments in a table (tracking number, status, origin, destination, expedited, payment status, last updated).
  - Filter shipments by status (Pending, In Transit, Delivered, Cancelled), origin, destination, expedited, or payment status (Pending, Paid).
  - Mark shipments as expedited using the "Expedite" button (if not already).
  - Update payment status to "Paid" using the "Pay" button (if not already).
  - View shipment history via "View History," opening a modal with actions (e.g., Created, Updated, Expedited), details, and timestamps.

### Admin Features
- **Admin Dashboard** (`/admin/dashboard`): Admins access a dedicated dashboard to:
  - **Manage Shipments**:
    - Create shipments with tracking number, status, origin, destination, and optional user assignment.
    - Update shipments (status, origin, destination, user).
    - Delete shipments, logging history.
    - View all shipments with advanced filters (status, origin, destination, user, expedited, payment status).
    - View shipment history in a modal.
  - **Manage Users**:
    - Create users with username, email, password, and role (user or admin).
    - Update user details (username, email, role, optional password reset).
    - Delete non-admin users.
    - View user history (create, update, delete actions) in a modal.
    - View all users in a table (ID, username, email, role).
  - **Access Control**: Only "admin" role users access this dashboard; others see "Access denied."

### Technical Notes
- **Authentication**: Uses JWT-based authentication with cookies (`access_token`). Tokens expire after 1 hour. Logout clears the token.
- **Database**: Stores users, shipments, and history (shipment and user) in SQLite (`data/shipping.db`).
- **Security**: Configure `JWT_SECRET_KEY` and `SECRET_KEY` via environment variables for production. Enable CSRF protection and HTTPS when deploying.

## Requirements
See `requirements.txt` for dependencies, including:
- Flask==2.3.2
- Flask-SQLAlchemy==3.0.5
- Flask-JWT-Extended==4.7.1
- Werkzeug==2.3.6

## Contributing
Submit issues or pull requests to the repository.

## License
MIT License