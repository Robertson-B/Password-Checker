import customtkinter as ctk # Better than tkinter
import math # For entropy
import re # Regular expressions for password checking
from decimal import Decimal # Allows the program to store massive numbers
import random # For generating random passwords
import string # For generating random passwords
import os # For clearing the console

# Define a modern color palette for the app
COLORS = {
    "background": "#F0F4F8",  # Light blue-gray
    "header": "#005A9E",  # Deep blue
    "text_primary": "#333333",  # Dark gray
    "text_secondary": "#555555",  # Subtle gray
    "button": "#0078D7",  # Blue
    "button_hover": "#005A9E",  # Darker blue
    "entry_bg": "#FFFFFF",  # White
    "entry_border": "#CCCCCC",  # Light gray
    "card_bg": "#FFFFFF",  # White for card-like frames
    "card_border": "#E0E0E0",  # Light gray for card borders
}

class PasswordCheckerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Configure the window
        self.title("Password Strength Checker")
        self.geometry("800x600")  # Large window size
        self.resizable(False, False)
        self.configure(bg=COLORS["background"])  # Use modern background color

        # Set light mode and custom theme
        ctk.set_appearance_mode("light") # Dark mode is for losers
        ctk.set_default_color_theme("MoonlitSky.json")  # Use the custom theme for redundancy in case i forgot to set custom colours

        # Create widgets
        self.create_widgets()

    def create_widgets(self):
        # Decorative header
        self.header_frame = ctk.CTkFrame(self, fg_color=COLORS["header"], corner_radius=0)
        self.header_frame.pack(fill="x")

        self.header_label = ctk.CTkLabel(
            self.header_frame,
            text="🔒 Password Strength Checker 🔒", # Emoji support
            font=("Helvetica", 30, "bold"),
            text_color="#FFFFFF",  # White text for contrast
        )
        self.header_label.pack(pady=15)

        # Sub-header
        self.sub_header_label = ctk.CTkLabel(
            self,
            text="Create strong passwords to keep your accounts safe!",
            font=("Helvetica", 16, "italic"),
            text_color=COLORS["text_primary"],
        )
        self.sub_header_label.pack(pady=(10, 20))

        # Frame for password entry and buttons
        self.card_frame = ctk.CTkFrame(
            self,
            fg_color=COLORS["card_bg"],
            corner_radius=15,
            border_width=2,
            border_color=COLORS["card_border"],
        )
        self.card_frame.pack(pady=(20, 20), padx=20)

        # Password entry
        self.password_entry = ctk.CTkEntry(
            self.card_frame,
            placeholder_text="Enter your password",
            font=("Helvetica", 16),
            width=400,
            fg_color=COLORS["entry_bg"],
            border_color=COLORS["entry_border"],
            text_color="#000000",  # Set text color to black
        )
        self.password_entry.pack(padx=20, pady=20)

        # Check Strength button
        self.check_button = ctk.CTkButton(
            self.card_frame,
            text="Check Strength",
            font=("Helvetica", 16),
            fg_color=COLORS["button"],
            hover_color=COLORS["button_hover"],
            corner_radius=10,
            command=self.check_password_strength,
        )
        self.check_button.pack(pady=10)

        # Generate Random Password button
        self.generate_button = ctk.CTkButton(
            self.card_frame,
            text="Generate Secure Password",
            font=("Helvetica", 16),
            fg_color="#4CAF50",  # Green button for generating passwords
            hover_color="#388E3C",  # Darker green on hover
            corner_radius=10,
            command=self.generate_secure_password,
        )
        self.generate_button.pack(pady=10)

        # Copy to Clipboard button
        self.copy_button = ctk.CTkButton(
            self.card_frame,
            text="Copy to Clipboard",
            font=("Helvetica", 16),
            fg_color="#FFA500",  # Orange button for copy
            hover_color="#CC8400",  # Darker orange on hover
            corner_radius=10,
            command=self.copy_password_to_clipboard,
        )
        self.copy_button.pack(pady=10)

        # Result label
        self.result_label = ctk.CTkLabel(
            self,
            text="",
            font=("Helvetica", 22, "bold"),
            text_color=COLORS["text_primary"],
        )
        self.result_label.pack(pady=(20, 10))

        # Feedback label
        self.feedback_label = ctk.CTkLabel(
            self,
            text="",
            font=("Helvetica", 14),
            text_color=COLORS["text_secondary"],
            wraplength=600,
            justify="left",
        )
        self.feedback_label.pack(pady=(10, 20))

        # Time to crack label
        self.time_to_crack_label = ctk.CTkLabel(
            self,
            text="",
            font=("Helvetica", 14),
            text_color=COLORS["text_secondary"],
            wraplength=600,
            justify="left",
        )
        self.time_to_crack_label.pack(pady=(10, 20))

        # Help button at the bottom right 
        self.help_button = ctk.CTkButton(
            self,
            text="Help",
            font=("Helvetica", 14),
            fg_color="#888888",
            hover_color="#555555",
            corner_radius=10,
            command=self.open_help_window,
        )
        # Use place for bottom-right positioning
        self.help_button.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-20)

        # About Developer button just left of Help
        self.about_button = ctk.CTkButton(
            self,
            text="About Developer",
            font=("Helvetica", 14),
            fg_color="#888888",
            hover_color="#555555",
            corner_radius=10,
            command=self.open_about_window,
        )
        self.about_button.place(relx=1.0, rely=1.0, anchor="se", x=-170, y=-20)  # 150px left of Help

    def open_help_window(self):
        if hasattr(self, "help_win") and self.help_win.winfo_exists(): # Why is this the only way to check if a window exists?
            self.help_win.lift()
            self.help_win.attributes("-topmost", True)
            return
        self.help_win = ctk.CTkToplevel(self)
        self.help_win.title("Help")
        self.help_win.geometry("400x300")
        self.help_win.resizable(False, False)
        help_label = ctk.CTkLabel(
            self.help_win,
            text=(
                "How to use Password Strength Checker:\n\n"
                "1. Enter a password in the box.\n"
                "2. Click 'Check Strength' to see how strong it is.\n"
                "3. Click 'Generate Secure Password' for a strong suggestion.\n"
                "4. Click 'Copy to Clipboard' to copy the password.\n"
                "5. Avoid using common or simple passwords (like 'passswors' or 'abc123').\n"
                "\nGreen means strong, red means weak. "
                "Try to use a mix of letters, numbers, and symbols!"
            ),
            font=("Helvetica", 13),
            wraplength=380,
            justify="left",
        )
        help_label.pack(padx=20, pady=20)
        self.help_win.attributes("-topmost", True)
        self.help_win.lift()

    def open_about_window(self): # I know this is a mess, but I don't care.
        if hasattr(self, "about_win") and self.about_win.winfo_exists():
            self.about_win.lift()
            self.about_win.attributes("-topmost", True)
            return
        self.about_win = ctk.CTkToplevel(self)
        self.about_win.title("About the Developer")
        self.about_win.geometry("400x200")
        self.about_win.resizable(False, False)
        about_label = ctk.CTkLabel(
            self.about_win,
            text=(
                "Password Checker\n"
                "Developed by BitRealm Games\n\n"
                "GitHub: https://github.com/Robertson-B\n"
                "Contact: BitRealmgames@gmail.com\n\n"
                "Thanks for using this app!"
            ),
            font=("Helvetica", 13),
            wraplength=380,
            justify="left",
        )
        about_label.pack(padx=20, pady=20)
        self.about_win.attributes("-topmost", True)
        self.about_win.lift()

    def generate_secure_password(self):
        #Generate a random, secure password with widely accepted special characters.
        length = 24  # Length of the generated password
        # Safer special characters for most sites
        safe_specials = "!@#$%^&*()-_=+[]{};:,.?/"
        characters = string.ascii_letters + string.digits + safe_specials
        password = "".join(random.choice(characters) for _ in range(length))
        self.password_entry.delete(0, "end")  # Clear the entry field
        self.password_entry.insert(0, password)  # Insert the generated password

    def check_password_strength(self):
        password = self.password_entry.get()

        # Easter egg for specific passwords
        if password.lower() in ["bean", "fong", "fongy", "ben", "password123"]:
            self.result_label.configure(text="Terrible", text_color="#FF5252")  # Red for bad passwords
            self.feedback_label.configure(text="That's a crap password! Try something more original!")
            self.time_to_crack_label.configure(text="")
            return

        # Regular password strength evaluation
        strength, color, feedback, time_to_crack = self.evaluate_password(password)
        self.result_label.configure(text=strength, text_color=color)
        self.feedback_label.configure(text=feedback)
        self.time_to_crack_label.configure(text=f"Estimated time to crack: {time_to_crack}")

    def evaluate_password(self, password):
        # Initialize feedback
        feedback = []

        # Determine character set size
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26  # Lowercase letters (a-z)
        else:
            feedback.append("Add at least one lowercase letter.")
        if re.search(r"[A-Z]", password):
            charset_size += 26  # Uppercase letters (A-Z)
        else:
            feedback.append("Add at least one uppercase letter.")
        if re.search(r"[0-9]", password):
            charset_size += 10  # Numbers (0-9)
        else:
            feedback.append("Add at least one number.")
        if re.search(r"[!\"#$%&'()*+,-./:;<=>?@\[\\\]^_`{|}~]", password):
            charset_size += 32  # Special characters (all valid printable symbols)
        else:
            feedback.append("Add at least one special character (e.g., !, @, #, etc.).")

        # Calculate entropy
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
        else:
            entropy = 0

        # Estimate time to crack using logarithms to avoid overflow
        guesses_per_second = Decimal(1e14)  # Assume 100 Trillion guesses per second

        try:
            log_total_guesses = Decimal(entropy)  # Use entropy directly in logarithmic form
            seconds_to_crack = Decimal(2) ** log_total_guesses / guesses_per_second

            # Heat death of the universe: ~1e100 years in seconds
            heat_death_seconds = Decimal("1e100") * Decimal(31536000)

            if seconds_to_crack > heat_death_seconds:
                time_to_crack = "Longer than the heat death of the universe! Probably pretty secure."
            elif seconds_to_crack < 60:
                time_to_crack = f"{seconds_to_crack:.2f} seconds"
            elif seconds_to_crack < 3600:
                time_to_crack = f"{seconds_to_crack / 60:.2f} minutes"
            elif seconds_to_crack < 86400:
                time_to_crack = f"{seconds_to_crack / 3600:.2f} hours"
            elif seconds_to_crack < 31536000:
                time_to_crack = f"{seconds_to_crack / 86400:.2f} days"
            else:
                time_to_crack = f"{seconds_to_crack / 31536000:.2f} years"
        except Exception:
            time_to_crack = "Inputted password is too large. Why do you need a password this long? Try something shorter."

        # Determine strength based on harsher entropy thresholds
        if entropy < 36:
            return "Weak", "#FF5252", " ".join(feedback), time_to_crack  # Red for weak passwords
        elif entropy < 60:
            return "Moderate", "#FFC107", " ".join(feedback), time_to_crack  # Yellow for moderate passwords
        elif entropy < 120:
            return "Strong", "#4CAF50", " ".join(feedback), time_to_crack  # Green for strong passwords
        else:
            return "Very Strong", "#66BB6A", "Your password is excellent!", time_to_crack  # Lighter green for very strong passwords

    def copy_password_to_clipboard(self): # Self explanatory
        password = self.password_entry.get()
        self.clipboard_clear()
        self.clipboard_append(password)


if __name__ == "__main__":
    os.system('cls||clear')  # Clear the console even for stupid macs
    print("\u001b[31;1mLook at the GUI, not the console.")
    print("\u001b[34m\u001b[0m", end="")
    app = PasswordCheckerApp()
    app.mainloop()