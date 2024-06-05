import logging.handlers
import tkinter as tk
from tkinter import messagebox, ttk
import random
import cryptography.fernet
import pyperclip
import json
import os
import shutil
import hashlib
import base64
import logging

# File paths and Global variables
base_dir = "users"
log_file = "password_manager.log"
credentials_file_path = os.path.join(base_dir, "credentials.json")
icon_file = "icon.ico"
logo_file = "logo.png"
encryption_key_file = "key.key"


handler = logging.handlers.RotatingFileHandler(filename=log_file, maxBytes=1, backupCount=3)
my_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_logger = logging.FileHandler(log_file,)
handler.setLevel(logging.INFO)
handler.setFormatter(my_formatter)

logger = logging.getLogger('password_manager')
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def Password_generator():
    password_entry.delete(0, 'end')

    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
               'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    nr_letters = random.randint(8, 10)
    nr_symbols = random.randint(2, 4)
    nr_numbers = random.randint(2, 4)

    password_list = []

    for char in range(nr_letters):
        password_list.append(random.choice(letters))

    for char in range(nr_symbols):
        password_list += random.choice(symbols)

    for char in range(nr_numbers):
        password_list += random.choice(numbers)

    random.shuffle(password_list)

    password = ""
    for char in password_list:
        password += char

    password_entry.insert(0, password)

    pyperclip.copy(password)


# ---------------------------- SAVE PASSWORD ------------------------------- #
def save_entries():
    website_text = website_entry.get()
    user_text = user_entry.get()
    password_text = password_entry.get()

    new_data = {
        website_text: {
            "user": user_text,
            "password": password_text,
        }
    }

    if not website_text or not password_text or not user_text:
        messagebox.showinfo("Warning", "One or more boxes is left blank ... please fill all boxes.")
        return

    try:
        with open(user_file_path, "r") as file:
            data = json.load(file)
            # Decrypt the data
            data = json.loads(decrypt_data(data['data'], key))
            if website_text in data:
                messagebox.showerror("Warning", f"The website {website_text} already has a user {user_text}!")
                return
    except FileNotFoundError:
        data = {}

    data.update(new_data)

    encrypted_data = encrypt_data(json.dumps(data), key)

    with open(user_file_path, "w") as file:
        json.dump({'data': encrypted_data}, file)

    website_entry.delete(0, 'end')
    password_entry.delete(0, 'end')
    user_entry.delete(0, 'end')

# ---------------------------- SEARCH PASSWORDS ------------------------------- #
def search_entries():
    partial_website = website_entry.get().casefold()
    results = []

    try:
        with open(user_file_path, 'r') as file:
            data = json.load(file)
            data = json.loads(decrypt_data(data['data'], key))
    except FileNotFoundError:
        messagebox.showinfo("Error", "No data file found")
        return

    for website, credentials in data.items():
        if partial_website in website.casefold():
            results.append((website, credentials["user"], credentials["password"]))

    if results:
        results_window = tk.Toplevel(main_window)
        results_window.title("Search Results")
        results_window.geometry("600x400")

        tree = ttk.Treeview(results_window, columns=("Website", "User", "Password"), show='headings')
        tree.heading("Website", text="Website")
        tree.heading("User", text="User")
        tree.heading("Password", text="Password")

        for result in results:
            tree.insert("", "end", values=result)

        tree.pack(fill='both', expand=True)

        scrollbar = ttk.Scrollbar(results_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        status_label = tk.Label(results_window, text="", anchor="w")
        status_label.pack(fill="x")

        def on_key_release(event):
            selected_item = tree.selection()
            if selected_item:
                values = tree.item(selected_item[0], "values")
                status_label.config(text=f"Website: {values[0]}, User: {values[1]}, Password: {values[2]}")
            else:
                status_label.config(text="")

        tree.bind("<KeyRelease>", on_key_release)
        tree.focus_set()
    else:
        messagebox.showinfo("Info", "No matching website found")


# ---------------------------- SHOW ALL PASSWORDS ------------------------------- #
def show_all_passwords():
    try:
        with open(user_file_path, 'r') as file:
            data = json.load(file)
            data = json.loads(decrypt_data(data['data'], key))
    except (FileNotFoundError, json.JSONDecodeError):
        messagebox.showinfo("Error", "No data file found")
        return

    if data:
        all_passwords_window = tk.Toplevel(main_window)
        all_passwords_window.title("All Stored Passwords")
        all_passwords_window.geometry("600x400")

        tree = ttk.Treeview(all_passwords_window, columns=("Website", "User", "Password"), show='headings')
        tree.heading("Website", text="Website")
        tree.heading("User", text="User")
        tree.heading("Password", text="Password")

        for website, info in data.items():
            tree.insert("", "end", values=(website, info["user"], info["password"]))

        tree.pack(fill='both', expand=True)

        def on_key_release(event):
            selected_item = tree.selection()
            if selected_item:
                values = tree.item(selected_item[0], "values")
                status_label.config(text=f"Website: {values[0]}, User: {values[1]}, Password: {values[2]}")
            else:
                status_label.config(text="")

        def delete_selected_item():
            selected_item = tree.selection()
            if selected_item:
                values = tree.item(selected_item[0], "values")
                website_to_delete = values[0]
                if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete {website} data?"):
                    del data[website_to_delete]
                    encrypted_data = encrypt_data(json.dumps(data), key)
                    with open(user_file_path, "w") as file:
                        json.dump({'data': encrypted_data}, file)
                    tree.delete(selected_item)
                    status_label.config(text="")
                    messagebox.showinfo("Success", f"{website} data has been deleted.")

        def edit_selected_item():
            selected_item = tree.selection()
            if selected_item:
                values = tree.item(selected_item[0], "values")
                website_to_edit = values[0]

                edit_window = tk.Toplevel(all_passwords_window)
                edit_window.title(f"Edit {website_to_edit}")
                edit_window.geometry("400x200")

                tk.Label(edit_window, text="User:").pack(pady=5)
                user_entry_edit = tk.Entry(edit_window)
                user_entry_edit.pack(pady=5)
                user_entry_edit.insert(0, values[1])

                tk.Label(edit_window, text="Password:").pack(pady=5)
                password_entry_edit = tk.Entry(edit_window, show='*')
                password_entry_edit.pack(pady=5)
                password_entry_edit.insert(0, values[2])

                def save_edits():
                    new_user = user_entry_edit.get()
                    new_password = password_entry_edit.get()
                    if not new_user or not new_password:
                        messagebox.showinfo("Warning", "One or more boxes is left blank ... please fill all boxes.")
                        return

                    data[website_to_edit] = {
                        "user": new_user,
                        "password": new_password
                    }
                    encrypted_data = encrypt_data(json.dumps(data), key)
                    with open(user_file_path, "w") as file:
                        json.dump({'data': encrypted_data}, file)

                    tree.item(selected_item[0], values=(website_to_edit, new_user, new_password))
                    edit_window.destroy()

                tk.Button(edit_window, text="Save", command=save_edits).pack(pady=15)

        tree.bind("<KeyRelease>", on_key_release)

        scrollbar = ttk.Scrollbar(all_passwords_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        status_label = tk.Label(all_passwords_window, text="", anchor="w")
        status_label.pack(fill="x")

        tk.Button(all_passwords_window, text="Delete Selected", command=delete_selected_item).pack(pady=10)
        tk.Button(all_passwords_window, text="Edit Selected", command=edit_selected_item).pack(pady=10)

        tree.focus_set()
    else:
        messagebox.showinfo("Info", "No passwords stored yet")


# ---------------------------- Hahing Utility ------------------------------- #
def hash_password(password):
    salt = os.urandom(16)  # Generate a random salt
    password_bytes = password.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha512', password_bytes, salt, 100000)  # Use PBKDF2-HMAC-SHA256
    hashed_password = base64.urlsafe_b64encode(salt + dk).decode('utf-8')  # Combine salt and hashed password
    return hashed_password


# ---------------------------- VERIFY PASSWORD ------------------------------- #
def verify_password(stored_password, provided_password):
    stored_password_bytes = base64.urlsafe_b64decode(stored_password.encode('utf-8'))
    salt = stored_password_bytes[:16]  # Extract the salt from the stored password
    stored_hash = stored_password_bytes[16:]

    password_bytes = provided_password.encode('utf-8')
    dk = hashlib.pbkdf2_hmac('sha512', password_bytes, salt, 100000)
    return stored_hash == dk


# ---------------------------- SAVE CREDENTIALS ------------------------------- #
def save_credentials(username, password):
    if not os.path.exists(base_dir):
        os.mkdir(base_dir)

    try:
        with open(credentials_file_path, 'r') as file:
            credentials = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        credentials = {}

    hashed_password = hash_password(password)
    credentials[username] = hashed_password
    with open(credentials_file_path, 'w') as file:
        json.dump(credentials, file)


# ---------------------------- VERIFY CREDENTIALS ------------------------------- #
def verify_credentials(username, password):
    if os.path.exists(credentials_file_path):
        with open(credentials_file_path, 'r') as file:
            credentials = json.load(file)
            stored_password = credentials.get(username)
            if stored_password:
                return verify_password(stored_password, password)
    return False
    

# ---------------------------- DELETE USERS ------------------------------- #
# Delete user and password from credentials file
def show_registered_users():
    try:
        with open(credentials_file_path, 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        messagebox.showinfo("Error", "No users are registered yet.")
        return

    all_users_window = tk.Toplevel(main_window)
    all_users_window.title("Registered Users")
    all_users_window.geometry("600x300")

    tree = ttk.Treeview(all_users_window, columns=('Username'), show='headings')
    tree.heading("Username", text="Username")

    for username in data.keys():
        tree.insert('', 'end', values=(username,))
    tree.pack(expand=True, fill="both")

    def delete_user():
            selected_item = tree.selection()
            if selected_item:
                username = tree.item(selected_item)['values'][0]
                if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete user '{username}'?"):
                    del data[username]
                    with open(credentials_file_path, "w") as file:
                        json.dump(data, file)
                    tree.delete(selected_item)
                    messagebox.showinfo("Success", f"User '{username}' has been deleted.")
                    logging.info(f"User '{username}' has been deleted.")
                    user_dir = os.path.join(base_dir, username)
                    shutil.rmtree(user_dir)
            else:
                messagebox.showwarning("Select User", "Please select a user to delete.")

    scrollbar = ttk.Scrollbar(all_users_window, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")

    tk.Button(all_users_window, text="Delete Selected", command=delete_user).pack(pady=10)
    tree.focus_set()

    all_users_window.mainloop()


# ---------------------------- ENCRYPTION / DECRYPTION ------------------------------- #
# Generate encryption key
def generate_key(user_dir):
    key = cryptography.fernet.Fernet.generate_key()
    with open(os.path.join(user_dir, encryption_key_file), 'wb') as key_file:
        key_file.write(key)


# Load encryption key
def load_key(user_dir):
    return open(os.path.join(user_dir, encryption_key_file), 'rb').read()


# Encrypting data
def encrypt_data(data, key):
    fernet = cryptography.fernet.Fernet(key)
    return fernet.encrypt(data.encode()).decode()


# Decrypting data
def decrypt_data(data, key):
    fernet = cryptography.fernet.Fernet(key)
    return fernet.decrypt(data.encode()).decode()


# ---------------------------- LOGIN WINDOW ------------------------------- #
def login():
    login_window = tk.Tk()
    login_window.title("Login to Passwords Manager")
    login_window.geometry("400x200")
    login_window.iconbitmap(icon_file)

    user_label = tk.Label(login_window, text="User:")
    password_label = tk.Label(login_window, text="Password:")

    user_entry = tk.Entry(login_window)
    user_entry.focus()
    password_entry = tk.Entry(login_window, show='*')

    user_label.pack(pady=5)
    user_entry.pack(pady=5)
    password_label.pack(pady=5)
    password_entry.pack(pady=5)

    def attempt_login(event=None):
        global key, user_file_path, username
        username = user_entry.get().casefold()
        password = password_entry.get()
        if verify_credentials(username, password):            
            user_dir = os.path.join(base_dir, username)
            user_file_path = os.path.join(user_dir, "passwords.json")
            key = load_key(user_dir)
            login_window.destroy()
            logger.info(f"{username} login successfull")
            main_app()            
        else:
            messagebox.showerror("Error", "Invalid credentials")
            logger.info(f"The user {username} couldn't login, either the user doesn't exist or invalid credentials")

    user_entry.bind("<Return>", attempt_login)
    password_entry.bind("<Return>", attempt_login)
    tk.Button(login_window, text="Login", command=attempt_login).pack(pady=15)
    login_window.mainloop()


# ---------------------------- SIGNUP WINDOW ------------------------------- #
def signup():
    signup_window = tk.Tk()
    signup_window.title("Sign up to Passwords Manager")
    signup_window.geometry("400x250")
    signup_window.iconbitmap(icon_file)

    user_label = tk.Label(signup_window, text="Create user:")
    password_label = tk.Label(signup_window, text="Create password:")
    pass_verify_label = tk.Label(signup_window, text="Verify password:")

    user_entry = tk.Entry(signup_window)
    user_entry.focus()
    password_entry = tk.Entry(signup_window, show='*')
    pass_verify_entry = tk.Entry(signup_window, show='*')

    user_label.pack(pady=5)
    user_entry.pack(pady=5)
    password_label.pack(pady=5)
    password_entry.pack(pady=5)
    pass_verify_label.pack(pady=5)
    pass_verify_entry.pack(pady=5)

    def create_account(event=None):
        username = user_entry.get()
        password = password_entry.get()
        password_verify = pass_verify_entry.get()
        if len(password) == 0 or len(username) == 0 or len(password_verify) == 0:
            messagebox.showerror("Error", f"Cant create the user {username }you left the username or password empty.")
            logger.info(f"Cant create the user {username }you left the username or password empty.")
        elif password != password_verify:
            messagebox.showerror("Error", "The passwords do not match, please try again")
            logger.info("The passwords do not match, please try again")
        else:
            user_dir = os.path.join(base_dir, username)
            if not os.path.exists(user_dir):
                os.mkdir(user_dir)
            save_credentials(username, password)
            generate_key(user_dir)
            messagebox.showinfo("Success", f"The user {username} created successfully")
            logger.info(f"The user {username} created successfully")
            signup_window.destroy()
            login()

    user_entry.bind("<Return>", create_account)
    password_entry.bind("<Return>", create_account)
    pass_verify_entry.bind("<Return>", create_account)        
    tk.Button(signup_window, text="Sign Up", command=create_account).pack(pady=15)

    signup_window.mainloop()


# ---------------------------- CHANGE USER PASSWORD ------------------------------- #
def change_password(event=None):    
    change_password_window = tk.Toplevel(main_window)
    change_password_window.title("Change Password")
    change_password_window.geometry("400x300")
    change_password_window.iconbitmap(icon_file)

    current_password_label = tk.Label(change_password_window, text="Current Password:")
    current_password_label.pack(pady=5)
    current_password_entry = tk.Entry(change_password_window, show='*')
    current_password_entry.pack(pady=5)
    
    new_password_label = tk.Label(change_password_window, text="New Password:")
    new_password_label.pack(pady=5)
    new_password_entry = tk.Entry(change_password_window, show='*')
    new_password_entry.pack(pady=5)
    
    verify_new_password_label = tk.Label(change_password_window, text="Verify New Password:")
    verify_new_password_label.pack(pady=5)
    verify_new_password_entry = tk.Entry(change_password_window, show='*')
    verify_new_password_entry.pack(pady=5)

    def submit_change():
        current_password = current_password_entry.get()
        new_password = new_password_entry.get()
        verify_new_password = verify_new_password_entry.get()
        
        if not verify_credentials(username, current_password):
            messagebox.showerror("Error", "Current password is incorrect.")
        elif new_password != verify_new_password:
            messagebox.showerror("Error", "New passwords do not match.")
        elif current_password == new_password:
            messagebox.showerror("Error", "The current password and the new password can't match.")
        elif len(new_password) == 0:
            messagebox.showerror("Error", "New password cannot be empty.")
        else:
            save_credentials(username, new_password)
            messagebox.showinfo("Success", "Password changed successfully.")
            change_password_window.destroy()

    current_password_entry.bind("<Return>", submit_change)
    new_password_entry.bind("<Return>", submit_change)
    verify_new_password_entry.bind("<Return>", submit_change)

    tk.Button(change_password_window, text="Submit", command=submit_change).pack(pady=15)
        
    change_password_window.mainloop().mainloop()


# ---------------------------- CREATE NEW USER ------------------------------- #
def new_user():
    new_user_window = tk.Tk()
    new_user_window.title("Create a new user")
    new_user_window.geometry("400x250")
    new_user_window.iconbitmap(icon_file)

    user_label = tk.Label(new_user_window, text="Create user:")
    password_label = tk.Label(new_user_window, text="Create password:")
    pass_verify_label = tk.Label(new_user_window, text="Verify password:")

    user_entry = tk.Entry(new_user_window)
    user_entry.focus()
    password_entry = tk.Entry(new_user_window, show='*')
    pass_verify_entry = tk.Entry(new_user_window, show='*')

    user_label.pack(pady=5)
    user_entry.pack(pady=5)
    password_label.pack(pady=5)
    password_entry.pack(pady=5)
    pass_verify_label.pack(pady=5)
    pass_verify_entry.pack(pady=5)

    def create_new_account(event=None):
        username = user_entry.get()
        password = password_entry.get()
        password_verify = pass_verify_entry.get()
        if len(password) == 0 or len(username) == 0 or len(password_verify) == 0:
            messagebox.showerror("Error", f"Can't create the user {username}. You left the username or password empty.")
            logger.info(f"Can't create the user {username}. You left the username or password empty.")
        elif password != password_verify:
            messagebox.showerror("Error", f"Can't create the user {username}. The passwords do not match, please try again")
            logger.info(f"Can't create the user {username}. The passwords do not match, please try again")
        else:
            user_dir = os.path.join(base_dir, username)
            if not os.path.exists(user_dir):
                os.mkdir(user_dir)
            save_credentials(username, password)
            generate_key(user_dir)
            messagebox.showinfo("Success", "Account created successfully")
            logger.info(f"User {username} created successfully")
            new_user_window.destroy()

    user_entry.bind("<Return>", create_new_account)
    password_entry.bind("<Return>", create_new_account)
    pass_verify_entry.bind("<Return>", create_new_account)        
    tk.Button(new_user_window, text="Create User", command=create_new_account).pack(pady=15)

    new_user_window.mainloop()
        

# ---------------------------- SWITCH USERS ------------------------------- #
def switch_user():
    main_window.destroy()
    login()


# ---------------------------- UI SETUP ------------------------------- #
def main_app():
    global main_window
    main_window = tk.Tk()
    main_window.title(f"Password Manager created by Amos Mesika - User: {username} v2.0")
    main_window.config(padx=40, pady=40)

    main_window.iconbitmap(icon_file)

    website = tk.StringVar()
    canvas = tk.Canvas(width=200, height=200)
    photo = tk.PhotoImage(file=logo_file)
    canvas.create_image(100, 100, image=photo)
    canvas.grid(column=1, row=0)

    website_label = tk.Label(text="Website:")
    website_label.grid(column=0, row=1)
    
    global website_entry
    website_entry = tk.Entry(width=36)
    website_entry.focus()
    website_entry.grid(row=1, column=1)

    user_label = tk.Label(text="Email/Username:")
    user_label.grid(column=0, row=2)

    global user_entry
    user_entry = tk.Entry(width=55)
    user_entry.grid(row=2, column=1, columnspan=2)

    password_label = tk.Label(text="Password:")
    password_label.grid(column=0, row=3)

    global password_entry
    password_entry = tk.Entry(width=36, show='*')
    password_entry.grid(row=3, column=1)

    pass_gen_button = tk.Button(text="Generate Password", command=Password_generator)
    pass_gen_button.grid(row=3, column=2)

    add_button = tk.Button(text="Add", width=47, command=save_entries)
    add_button.grid(row=4, column=1, columnspan=2)

    search_button = tk.Button(text="Search", width=15, command=search_entries)
    search_button.grid(row=1, column=2)

    show_all_button = tk.Button(text="Show all passwords", width=47, command=show_all_passwords)
    show_all_button.grid(row=5, column=1, columnspan=2)

    # Add a menu bar
    menubar = tk.Menu(main_window)
    # Add File Menu and commands
    file_menu = tk.Menu(menubar, tearoff = 0)
    menubar.add_cascade(label = 'File', menu = file_menu)
    file_menu.add_command(label = 'New User', command=new_user)
    file_menu.add_command(label="Switch User", command=switch_user)
    file_menu.add_command(label="Change Password", command=change_password)
    file_menu.add_command(label="Delete user", command=show_registered_users)
    file_menu.add_command(label = 'Exit', command=main_window.destroy)
    file_menu.add_separator()
    
    
    main_window.config(menu = menubar)

    main_window.mainloop()


# ---------------------------- ENTRY POINT ------------------------------- #
if not os.path.exists(base_dir):
    os.makedirs(base_dir)
if not os.path.exists(credentials_file_path) or os.stat(credentials_file_path).st_size == 0:
    signup()
else:
    login()
