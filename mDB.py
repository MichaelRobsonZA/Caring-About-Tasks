import subprocess

def migrate(message):
    try:
        # Generate a migration script
        subprocess.run(["flask", "db", "migrate", "-m", message], check=True)

        # Apply the migration to the database
        subprocess.run(["flask", "db", "upgrade"], check=True)

        print("Migration successful.")
    except subprocess.CalledProcessError as e:
        print("Migration failed.")
        print("Error:", e)

if __name__ == "__main__":
    message = input("Enter a message for the migration: ")
    if not message:
        message = "Default migration message"  # Default message
    migrate(message)