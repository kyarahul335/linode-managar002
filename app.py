from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_file, session
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os
import io
import uuid  # For generating random keys
from database import get_db, close_db

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management

# File to store keys and tokens
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
key_file = os.path.join(BASE_DIR, "keys.json")

# Ensure the keys file exists
if not os.path.exists(key_file):
    with open(key_file, "w") as file:
        json.dump({}, file)

def load_keys():
    db = get_db()
    keys = db.execute('SELECT * FROM keys').fetchall()
    key_data = {}
    for key in keys:
        tokens = db.execute('SELECT * FROM tokens WHERE key_id = ?', (key['id'],)).fetchall()
        key_data[key['user_key']] = {
            "total_limit": key['total_limit'],
            "available_limit": key['available_limit'],
            "tokens": [dict(token) for token in tokens]
        }
    return key_data

def save_keys(keys):
    db = get_db()
    for user_key, key_data in keys.items():
        # Update or insert key
        db.execute('INSERT OR REPLACE INTO keys (user_key, total_limit, available_limit) VALUES (?, ?, ?)',
                   (user_key, key_data['total_limit'], key_data['available_limit']))
        key_id = db.execute('SELECT id FROM keys WHERE user_key = ?', (user_key,)).fetchone()['id']
        # Delete existing tokens for the key
        db.execute('DELETE FROM tokens WHERE key_id = ?', (key_id,))
        # Insert new tokens
        for token in key_data['tokens']:
            db.execute('INSERT INTO tokens (key_id, account_name, token) VALUES (?, ?, ?)',
                       (key_id, token['account_name'], token['token']))
    db.commit()

# Admin password (change this to a strong password)
ADMIN_PASSWORD = "Azure@5964@#9812#"

# Admin login route
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            flash("Admin login successful.")
            return redirect(url_for("admin_panel"))
        else:
            flash("Invalid password.")
    return render_template("admin_login.html")

# Admin logout route
@app.route("/admin/logout", methods=["GET", "POST"])
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Admin logged out.")
    return redirect(url_for("index"))

# Admin panel route
@app.route("/admin", methods=["GET", "POST"])
def admin_panel():
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if request.method == "POST":
        if 'add_key' in request.form:
            # Add a manual key
            user_key = request.form.get("user_key")
            if user_key:
                keys[user_key] = {"total_limit": 0, "available_limit": 0, "tokens": []}  # Default limit is 0
                save_keys(keys)
                flash(f"Key '{user_key}' added successfully.")
            else:
                flash("Please enter a valid key.")

        elif 'generate_key' in request.form:
            # Generate a random key
            user_key = str(uuid.uuid4())  # Generate a random UUID
            keys[user_key] = {"total_limit": 0, "available_limit": 0, "tokens": []}  # Default limit is 0
            save_keys(keys)
            flash(f"Random key '{user_key}' generated successfully.")

        elif 'delete_key' in request.form:
            # Delete a key
            key_to_delete = request.form.get("key_to_delete")
            if key_to_delete in keys:
                del keys[key_to_delete]
                save_keys(keys)
                flash(f"Key '{key_to_delete}' deleted successfully.")
            else:
                flash("Key not found.")

        elif 'update_limit' in request.form:
            # Update limit for a key
            key_to_update = request.form.get("key_to_update")
            new_limit = int(request.form.get("new_limit"))
            if key_to_update in keys:
                # Ensure the key has the required fields
                if "total_limit" not in keys[key_to_update]:
                    keys[key_to_update]["total_limit"] = 0
                if "available_limit" not in keys[key_to_update]:
                    keys[key_to_update]["available_limit"] = 0

                # Calculate the new available_limit
                current_available_limit = keys[key_to_update]["available_limit"]
                keys[key_to_update]["total_limit"] += new_limit
                keys[key_to_update]["available_limit"] += new_limit
                save_keys(keys)
                flash(f"Limit updated successfully for key '{key_to_update}'. New total limit: {keys[key_to_update]['total_limit']}, New available limit: {keys[key_to_update]['available_limit']}.")
            else:
                flash("Key not found.")

    # Prepare data to show keys and their linked tokens
    key_token_pairs = []
    for key, key_data in keys.items():
        # Ensure the key has the required fields
        if "total_limit" not in key_data:
            key_data["total_limit"] = 0
        if "available_limit" not in key_data:
            key_data["available_limit"] = 0

        tokens = key_data.get("tokens", [])
        total_limit = key_data["total_limit"]
        available_limit = key_data["available_limit"]
        key_token_pairs.append({
            "key": key,
            "tokens": tokens,
            "total_limit": total_limit,
            "available_limit": available_limit
        })

    return render_template("admin_panel.html", key_token_pairs=key_token_pairs)

# Add token route
@app.route("/add_token", methods=["POST"])
def add_token():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    account_name = request.form.get("account_name")
    token = request.form.get("token")
    keys = load_keys()

    # Get the user key from the session
    user_key = session['user_key']

    # Debugging: Print the current keys before adding the token
    print("Current keys before adding token:", keys)

    # Check if the key exists in keys.json
    if user_key in keys:
        # Add the new token to the key's token list
        keys[user_key]["tokens"].append({
            "account_name": account_name,
            "token": token
        })
    else:
        # If the key doesn't exist, create a new entry
        keys[user_key] = {
            "tokens": [{
                "account_name": account_name,
                "token": token
            }]
        }

    # Debugging: Print the updated keys after adding the token
    print("Updated keys after adding token:", keys)

    # Save the updated keys to the file
    save_keys(keys)
    flash("Token added successfully.")
    return redirect(url_for("index"))


# Add this route to view tokens
@app.route("/view_tokens")
def view_tokens():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No tokens found for your key.")
        return redirect(url_for("index"))

    tokens = keys[user_key]["tokens"]
    return render_template("view_tokens.html", tokens=tokens)

@app.route("/admin/add_token/<key>", methods=["POST"])
def admin_add_token(key):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    account_name = request.form.get("account_name")
    token = request.form.get("token")

    keys = load_keys()

    if key in keys:
        keys[key]["tokens"].append({
            "account_name": account_name,
            "token": token
        })
        save_keys(keys)
        flash(f"Token added successfully for key '{key}'.")
    else:
        flash(f"Key '{key}' not found.")

    return redirect(url_for("admin_panel"))

@app.route("/admin/remove_token/<key>/<int:token_index>", methods=["POST"])
def admin_remove_token(key, token_index):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if key in keys:
        tokens = keys[key]["tokens"]
        if token_index < len(tokens):
            removed_token = tokens.pop(token_index)
            save_keys(keys)
            flash(f"Token '{removed_token['token']}' removed successfully for key '{key}'.")
        else:
            flash("Invalid token index.")
    else:
        flash(f"Key '{key}' not found.")

    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_key/<key>", methods=["POST"])
def admin_delete_key(key):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if key in keys:
        del keys[key]
        save_keys(keys)
        flash(f"Key '{key}' deleted successfully.")
    else:
        flash(f"Key '{key}' not found.")

    return redirect(url_for("admin_panel"))


@app.route("/admin/edit_token/<key>/<int:token_index>", methods=["GET", "POST"])
def admin_edit_token(key, token_index):
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.")
        return redirect(url_for("admin_login"))

    keys = load_keys()

    if key not in keys:
        flash(f"Key '{key}' not found.")
        return redirect(url_for("admin_panel"))

    tokens = keys[key]["tokens"]
    if token_index >= len(tokens):
        flash("Invalid token index.")
        return redirect(url_for("admin_panel"))

    if request.method == "POST":
        account_name = request.form.get("account_name")
        token = request.form.get("token")

        tokens[token_index] = {
            "account_name": account_name,
            "token": token
        }
        save_keys(keys)
        flash(f"Token updated successfully for key '{key}'.")
        return redirect(url_for("admin_panel"))

    token = tokens[token_index]
    return render_template("edit_token.html", key=key, token_index=token_index, token=token)

# Add this route to edit a token
@app.route("/edit_token/<int:token_index>", methods=["GET", "POST"])
def edit_token(token_index):
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No tokens found for your key.")
        return redirect(url_for("index"))

    tokens = keys[user_key]["tokens"]
    if token_index >= len(tokens):
        flash("Invalid token index.")
        return redirect(url_for("view_tokens"))

    if request.method == "POST":
        account_name = request.form.get("account_name")
        token = request.form.get("token")
        tokens[token_index] = {"account_name": account_name, "token": token}
        save_keys(keys)
        flash("Token updated successfully.")
        return redirect(url_for("view_tokens"))

    token = tokens[token_index]
    return render_template("edit_token.html", token=token, token_index=token_index)

# Add this route to delete a token
@app.route("/delete_token/<int:token_index>", methods=["POST"])
def delete_token(token_index):
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No tokens found for your key.")
        return redirect(url_for("index"))

    tokens = keys[user_key]["tokens"]
    if token_index >= len(tokens):
        flash("Invalid token index.")
        return redirect(url_for("view_tokens"))

    del tokens[token_index]
    save_keys(keys)
    flash("Token deleted successfully.")
    return redirect(url_for("view_tokens"))

# Function to validate root password
def validate_password(password):
    if (
        len(password) >= 14
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and sum(c in "!@#$%^&*()-_+=<>?/" for c in password) >= 2
    ):
        return True
    return False

# Function to create a Linode instance
def create_linode_instance(instance_number, results, image, region, instance_type, root_password, token, user_key):
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    label = f"{region}-{instance_type}-{instance_number}-{timestamp}"
    data = {
        "image": image,
        "private_ip": False,
        "region": region,
        "type": instance_type,
        "label": label,
        "root_pass": root_password
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.post("https://api.linode.com/v4/linode/instances", headers=headers, data=json.dumps(data))
    if response.status_code == 200 or response.status_code == 201:
        instance_data = response.json()
        results.append(instance_data.get("ipv4", [])[0])

        # Update available_limit for the user's key
        keys = load_keys()
        if user_key in keys:
            keys[user_key]["available_limit"] -= 1
            save_keys(keys)
    else:
        flash(f"Failed to create Linode instance {instance_number}: {response.json()}")

# Function to delete a Linode instance
def delete_linode_instance(instance_id, token):
    url = f"https://api.linode.com/v4/linode/instances/{instance_id}"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.delete(url, headers=headers)
    if response.status_code == 200 or response.status_code == 204:
        flash(f"Linode instance {instance_id} deleted successfully.")
    else:
        flash(f"Failed to delete Linode instance {instance_id}: {response.json()}")

# Function to list all Linode instances
def list_linode_instances(token):
    url = "https://api.linode.com/v4/linode/instances"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("data", [])
    else:
        flash(f"Failed to retrieve Linode instances: {response.json()}")
        return []

@app.route("/")
def index():
    keys = load_keys()
    if 'user_key' in session:
        user_key = session['user_key']
        if user_key in keys:
            tokens = {token["account_name"]: token["token"] for token in keys[user_key]["tokens"]}
            available_limit = keys[user_key].get("available_limit", 0)
            total_limit = keys[user_key].get("total_limit", 0)
            return render_template("index.html", tokens=tokens, keys=keys, available_limit=available_limit, total_limit=total_limit)
    return render_template("index.html", tokens={}, keys=keys, available_limit=0, total_limit=0)

@app.route("/validate_key", methods=["POST"])
def validate_key():
    user_key = request.form.get("user_key")
    keys = load_keys()
    if user_key in keys:
        session['user_key'] = user_key
        flash("Key validated successfully.")
    else:
        flash("Invalid key.")
    return redirect(url_for("index"))

@app.route("/logout", methods=["POST"])  # Allow POST for logout
def logout():
    session.pop('user_key', None)  # Clear the session
    flash("You have been logged out.")
    return redirect(url_for('index'))

@app.route("/create_instances", methods=["POST"])
def create_instances():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No token found for your key.")
        return redirect(url_for("index"))

    # Check available limit
    available_limit = keys[user_key].get("available_limit", 0)
    num_instances = int(request.form.get("num_instances"))

    if num_instances > available_limit:
        flash(f"You have reached your limit. You can only create {available_limit} more instances.")
        return redirect(url_for("index"))

    token = request.form.get("token")
    image = request.form.get("image")
    region = request.form.get("region")
    instance_type = request.form.get("instance_type")
    root_password = request.form.get("root_password")

    if not validate_password(root_password):
        flash("Invalid password. Please try again.")
        return redirect(url_for("index"))

    ips = []
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(create_linode_instance, i, ips, image, region, instance_type, root_password, token, user_key)
            for i in range(1, num_instances + 1)
        ]
        for future in futures:
            future.result()

    if ips:
        # Create a text file with the instance details
        file_content = f"Region: {region}\nInstance Type: {instance_type}\nRoot Password: {root_password}\nIPs:\n"
        file_content += "\n".join(ips)
        file_stream = io.BytesIO(file_content.encode('utf-8'))
        file_stream.seek(0)
        return send_file(file_stream, as_attachment=True, download_name=f"{region}_{instance_type}_instances.txt", mimetype='text/plain')

    flash("No instances were created.")
    return redirect(url_for("index"))

@app.route("/delete_instances", methods=["POST"])
def delete_instances():
    if 'user_key' not in session:
        flash("Please enter a valid key first.")
        return redirect(url_for("index"))

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        flash("No token found for your key.")
        return redirect(url_for("index"))

    token = request.form.get("token")
    instance_ids = request.form.getlist("instance_ids")  # Get selected instance IDs

    if not instance_ids:
        flash("No instances selected for deletion.")
        return redirect(url_for("index"))

    for instance_id in instance_ids:
        delete_linode_instance(instance_id, token)

    flash("Selected instances deleted successfully.")
    return redirect(url_for("index"))

@app.route("/get_instances")
def get_instances():
    if 'user_key' not in session:
        return jsonify([])

    keys = load_keys()
    user_key = session['user_key']
    if user_key not in keys:
        return jsonify([])

    token = request.args.get("token")
    instances = list_linode_instances(token)
    return jsonify(instances)

if __name__ == "__main__":
    app.run(debug=True)