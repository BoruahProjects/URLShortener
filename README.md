Cloudflare URL Shortener
========================

This is a powerful, self-hosted URL shortener built to run on the Cloudflare ecosystem. It uses **Cloudflare Workers** for the backend logic, **Cloudflare Pages** for the frontend dashboard, and **Cloudflare D1** for the database.

🚀 Features
-----------

*   **Admin Dashboard**: A secure, login-protected dashboard to manage all your links.
*   **Link Shortening**: Create custom, short, and easy-to-share links.
*   **Folder Organization**: Group your links into folders for better management.
*   **Password Protection**: Secure your links with a password.
*   **Expiration Dates**: Set links to expire after a specific date and time.
*   **Click Limits**: Configure links to become inactive after a certain number of clicks.
*   **Search and Filter**: Easily find links by searching for paths or original URLs, and filter by clicks or expiration status.
*   **Sort Functionality**: Sort links by creation date, number of clicks, or path name.
*   **Secure**: Implements CSRF protection, rate limiting, and secure authentication practices.

🛠️ Tech Stack
--------------

*   **Backend**: Cloudflare Workers
*   **Frontend**: Cloudflare Pages (HTML, CSS, JavaScript)
*   **Database**: Cloudflare D1

📁 Project Structure
--------------------

Here's an overview of the key files in this project:

    .
    ├── workers.js                # Cloudflare Worker script (Backend API and logic)
    ├── index.html                # Main HTML file for the admin dashboard
    ├── dashboard.js              # JavaScript for the admin dashboard functionality
    ├── style.css                 # CSS for styling the application
    ├── password_protected.html   # HTML page for password-protected links
    ├── password-page.js          # JavaScript for the password submission page
    └── README.md                 # This README file
    

*   `workers.js`: This is the heart of the application. It's a Cloudflare Worker that handles all API requests, authentication, database interactions, and link redirection logic.
*   `index.html`: The single-page application for the admin dashboard.
*   `dashboard.js`: Contains all the client-side logic for the dashboard, including API calls, rendering links, and handling user interactions.
*   `style.css`: Provides the styling for both the admin dashboard and the password prompt page.
*   `password_protected.html`: The page shown to users when they access a password-protected link.
*   `password-page.js`: The client-side script that handles the password submission for protected links.

⚙️ Deployment Guide
-------------------

Follow these steps to deploy the URL shortener on Cloudflare.

### Step 1: Set up Cloudflare D1 Database

1.  Navigate to your Cloudflare dashboard.
2.  Go to **Workers & Pages** > **D1**.
3.  Click **Create database**. Give it a name (e.g., `url-shortener-db`).
4.  Once created, open the database console and run the following SQL schema to create the necessary tables:
    
        CREATE TABLE items (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL, -- 'link' or 'folder'
            name TEXT, -- For folders
            original_url TEXT, -- For links
            password_hash TEXT,
            clicks INTEGER DEFAULT 0,
            max_clicks INTEGER DEFAULT 0,
            expires_at INTEGER,
            created_at INTEGER NOT NULL,
            parent_id TEXT,
            FOREIGN KEY (parent_id) REFERENCES items(id) ON DELETE CASCADE
        );
        
        CREATE TABLE sessions (
            session_token TEXT PRIMARY KEY,
            csrf_token_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_activity_at INTEGER NOT NULL,
            ip_address TEXT NOT NULL
        );
        
        CREATE TABLE admin_session (
            id INTEGER PRIMARY KEY,
            session_token TEXT NOT NULL
        );
        
        CREATE TABLE login_attempts (
            key TEXT PRIMARY KEY,
            attempts INTEGER DEFAULT 1,
            last_attempt_timestamp INTEGER NOT NULL,
            blocked_until INTEGER,
            block_count INTEGER DEFAULT 0
        );
        
        CREATE TABLE rate_limits (
            key TEXT PRIMARY KEY,
            timestamps TEXT NOT NULL
        );
        
        CREATE INDEX idx_items_parent_id ON items(parent_id);
        CREATE INDEX idx_items_type ON items(type);
        
    

### Step 2: Set up the Cloudflare Worker

1.  Go to **Workers & Pages** and click **Create application**.
2.  Select **Create Worker**.
3.  Give your Worker a name (e.g., `url-shortener-api`) and deploy it.
4.  Go to the Worker's **Bindings** tab.
5.  Click on **Add binding** and select **D1 Database**, .
    *   **Variable name**: `DB`
    *   **D1 Database**: Select the database you created in Step 1.
6.  Goto **Settings** and **Variables and Secrets**, add the following secrets for your admin credentials. You will need to generate SHA-256 hashes for your chosen username and password.
    
    *   `ADMIN_USERNAME_HASH`: The SHA-256 hash of your desired admin username.
    *   `ADMIN_PASSWORD_HASH`: The SHA-256 hash of your desired admin password.
    
    You can use an online tool or a command-line utility to generate these hashes.
    
7.  Copy the code from `workers.js` and paste it into the Worker's code editor.
8.  Click **Save and Deploy**.

### Step 3: Configure and Deploy the Frontend on Cloudflare Pages

1.  Before deploying, you need to update the API endpoint in the frontend files. In `dashboard.js` and `password-page.js`, change the `WORKER_API_URL` constant to your Worker's URL.
    
        // In dashboard.js and password-page.js
        const WORKER_API_URL = 'https://your-worker-name.your-subdomain.workers.dev/api';
        
    
2.  Go to **Workers & Pages** and click **Create application**.
3.  Select the **Pages** tab.
4.  Choose **Upload assets**.
5.  Give your project a name (e.g., `url-shortener-frontend`).
6.  Upload the frontend files: `index.html`, `dashboard.js`, `style.css`, `password_protected.html`, and `password-page.js`.
7.  Deploy the site.

### Step 4: Set up Custom Domain and Routing

1.  It's recommended to use a custom domain for your shortener (e.g., `links.yourdomain.com`).
2.  Point your custom domain to the Cloudflare Worker. In your domain's DNS settings in Cloudflare, create a CNAME record pointing your desired subdomain to your worker's URL (`your-worker-name.your-subdomain.workers.dev`).
3.  In your Worker's settings, go to the **Triggers** tab and add a route for your custom domain (e.g., `links.yourdomain.com/*`).
4.  The frontend dashboard can be on a different domain or subdomain (e.g., `short.yourdomain.com`). Make sure the `Access-Control-Allow-Origin` in `workers.js` is updated to your frontend's domain.

🖥️ Usage
---------

*   **Login**: Access the frontend URL you deployed on Cloudflare Pages. You will be prompted to log in with the admin credentials you configured.
*   **Creating Links/Folders**: Use the "Create Short URL" and "Create Folder" buttons.
*   **Managing Items**: Click on the action icons in the table to copy, edit, move, or delete links and folders.
*   **Navigation**: Click on a folder to navigate into it. Use the "Back" button to go to the parent folder.

## License

This project is licensed under a custom license. Please refer to the `LICENSE` file for details.
