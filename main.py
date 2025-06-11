import customtkinter as ctk # Better than tkinter and gooeypie
import math # For entropy
import re # Regular expressions for password checking
from decimal import Decimal # Allows the program to store massive numbers
import random  # For generating random passwords
import string  # For generating random passwords
import os  # For clearing the console
import urllib.request # For checking if the password is in a public GitHub list of common passwords
import webbrowser # For easter eggs
import pwnedpass # For checking if the password has been pwned in data breaches
import tkinter as tk # for secret minigames


# Define a modern color palette for the app
COLORS = {
    "background": "#F0F4F8",  
    "header": "#005A9E", 
    "text_primary": "#333333",  
    "text_secondary": "#555555",  
    "button": "#0078D7",  
    "button_hover": "#005A9E",  
    "button_border": "#313B6E", 
    "entry_bg": "#FFFFFF",  
    "entry_border": "#CCCCCC",  
    "card_bg": "#FFFFFF",  
    "window_bg": "#565c99",
    "card_border": "#E0E0E0",  
    "button_border": "#313B6E",
}

# Define allowed characters for password input
ALLOWED_PASSWORD_CHARS = string.ascii_letters + string.digits + "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

class PasswordCheckerApp(ctk.CTk): # One massive class. best way to do it.
    def __init__(self):
        super().__init__()

        # Configure the window
        self.title("Password Strength Checker")
        self.geometry("800x600") 
        self.resizable(False, False)
        self.configure(bg=COLORS["background"])  # Use modern background color
        ctk.set_appearance_mode("light") # Dark mode is for losers

        # Create widgets
        self.create_widgets()

        # Konami code variables
        self.konami_progress = ""
        self.konami_code = "upupdowndownleftrightleftrightba"
        # Developer access code variables
        self.dev_code_progress = ""
        self.dev_code = "bitrealm"
        # Minigame code variables
        self.minigame_code_progress = ""
        self.minigame_code = "snakegame"

        # Bind key events for secret buttons and Easter eggs
        self.bind_all("<Key>", self.key_listener)
        self.bind_all("<Escape>", self.show_self_destruct_button)

        self.secret_theme_on = False
        self.show_password = False
        self.toggle_clicks = 0

    def create_widgets(self):
        # Decorative header
        self.header_frame = ctk.CTkFrame(self, fg_color=COLORS["header"], corner_radius=0)
        self.header_frame.pack(fill="x")

        self.header_label = ctk.CTkLabel(
            self.header_frame,
            text="🔒 Password Strength Checker 🔒", # Emoji support
            font=("Helvetica", 30, "bold"), # Helvetica on top
            text_color="#FFFFFF",  
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
        self.card_frame.pack(pady=(0, 10), padx=20)

        # Password entry
        vcmd = self.register(self.validate_password_input) # Vallidates input in real time
        self.password_entry = ctk.CTkEntry(
            self.card_frame,
            placeholder_text="Enter your password",
            font=("Helvetica", 16),
            width=400,
            fg_color=COLORS["entry_bg"],
            border_color=COLORS["entry_border"],
            text_color="#000000",
            validate="key", # Validate input on every key press
            validatecommand=(vcmd, "%P"), # Pass the new value to the validation function
            # I know it looks like a mess, but this is the only way to validate input in real time in customtkinter.
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
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.check_password_strength,
        )
        self.check_button.pack(pady=10)

        # Generate Random Password button
        self.generate_button = ctk.CTkButton(
            self.card_frame,
            text="Generate Secure Password",
            font=("Helvetica", 16),
            fg_color="#4CAF50", 
            hover_color="#388E3C",  
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.generate_secure_password,
        )
        self.generate_button.pack(pady=10)

        # Copy to Clipboard button
        self.copy_button = ctk.CTkButton(
            self.card_frame,
            text="Copy to Clipboard",
            font=("Helvetica", 16),
            fg_color="#FFA500",  
            hover_color="#CC8400",  
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.copy_password_to_clipboard,
        )
        self.copy_button.pack(pady=10)

        # Password strength meter (progress bar)
        self.strength_bar = ctk.CTkProgressBar(
            self.card_frame,
            width=400,
            height=16,
            corner_radius=8,
        )
        self.strength_bar.set(0.0)
        self.strength_bar.pack(pady=(5, 10))
        self.strength_bar.configure(progress_color="#989ca4")

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
        self.time_to_crack_label.pack(pady=(0, 0))  

        # Pwned count label 
        self.pwned_count_label = ctk.CTkLabel(
            self,
            text="",
            font=("Helvetica", 14),
            text_color="#FF5252",
            wraplength=600,
            justify="left",
        )
        self.pwned_count_label.pack(pady=(0, 10))  

        # Spacer to push buttons down. Keeps them in place on diffrent screen sizes.
        ctk.CTkLabel(self, text="").pack(expand=True, fill="both")  

        # Help button at the bottom right 
        self.help_button = ctk.CTkButton(
            self,
            text="Help",
            font=("Helvetica", 14),
            fg_color="#888888",
            hover_color="#555555",
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.open_help_window,
        )
        self.help_button.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-20)

        # About Developer button just left of Help
        self.about_button = ctk.CTkButton(
            self,
            text="About Developer",
            font=("Helvetica", 14),
            fg_color="#888888",
            hover_color="#555555",
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.open_about_window,
        )
        self.about_button.place(relx=1.0, rely=1.0, anchor="se", x=-170, y=-20)  # 150px left of Help

        # Hidden button (not packed by default) for Easter egg
        self.hidden_button = ctk.CTkButton(
            self,
            text="Secret Button",
            font=("Helvetica", 14),
            fg_color="#FF69B4",
            hover_color="#C71585",
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.hallidays_egg,
        )

        # Tiny random joke button in the bottom right corner
        self.joke_button = ctk.CTkButton(
            self,
            text=".",
            width=10,
            height=10,
            fg_color="#FFFFFF",
            hover_color="#DDDDDD",
            text_color="#FFFFFF",
            border_width=0,
            corner_radius=5,
            command=self.show_random_joke,
        )
        self.joke_button.place(relx=1.0, rely=1.0, anchor="se", x=-5, y=-5)

        # Secret colour swap
        self.header_label.bind("<Double-Button-1>", self.toggle_secret_theme)

        # Self-destruct button (hidden by default)
        self.self_destruct_button = ctk.CTkButton(
            self,
            text="Self-Destruct",
            font=("Helvetica", 14, "bold"),
            fg_color="#FF0000",
            hover_color="#880000",
            text_color="#FFFFFF",
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.self_destruct_sequence,
        )

        # Developer area button (not packed by default)
        self.dev_area_button = ctk.CTkButton(
            self,
            text="Dev Area",
            font=("Helvetica", 14, "bold"),
            fg_color="#222831",
            hover_color="#005A9E",
            text_color="#FFFFFF",
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.open_dev_area_quiz,
        )

        # Toggle password visibility button
        self.toggle_button = ctk.CTkButton(
            self,
            text="     👁️",
            font=("Helvetica", 16),
            fg_color="#888888",
            hover_color="#555555",
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.toggle_password_visibility,
            width=100,
            height=32,
        )
        # Place above and inline with the help button (bottom right, just above Help)
        self.toggle_button.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-70)

    def open_help_window(self): # Help window with instructions on how to use the app.
        if hasattr(self, "help_win") and self.help_win.winfo_exists(): # Why is this the only way to check if a window exists?
            self.help_win.lift()
            self.help_win.attributes("-topmost", True)
            return
        self.help_win = ctk.CTkToplevel(self)
        self.help_win.title("Help")
        self.help_win.geometry("400x300")
        self.help_win.resizable(False, False)
        self.help_win.configure(fg_color=COLORS["window_bg"])
        help_label = ctk.CTkLabel(
            self.help_win,
            text=(
                "How to use Password Strength Checker:\n\n"
                "1. Enter a password in the box.\n"
                "2. Click 'Check Strength' to see how strong it is.\n"
                "3. Click 'Generate Secure Password' for a strong suggestion.\n"
                "4. Click 'Copy to Clipboard' to copy the password.\n"
                "5. Avoid using common or simple passwords (like 'passsword' or 'abc123').\n"
                "\nGreen means strong, red means weak. "
                "Try to use a mix of letters, numbers, and symbols!"
            ),
            font=("Helvetica", 13),
            wraplength=380,
            justify="left",
            text_color="#FFFFFF"
        )
        help_label.pack(padx=20, pady=20)
        self.help_win.attributes("-topmost", True) # Keep the help window on top
        self.help_win.lift()

    def open_about_window(self): # I know this is a mess, but I don't care.
        if hasattr(self, "about_win") and self.about_win.winfo_exists():
            self.about_win.lift()
            self.about_win.attributes("-topmost", True)
            return
        self.about_win = ctk.CTkToplevel(self)
        self.about_win.title("About the Developer")
        self.about_win.geometry("400x240")
        self.about_win.resizable(False, False)
        self.about_win.configure(fg_color=COLORS["window_bg"])

        about_text = (
            "Password Checker\n"
            "Developed by BitRealm Games\n\n"
            "Created using Python and CustomTkinter.\n"
            "And absolute hatred for tkinter and gooeypie\n\n"
            "Thanks for using this app!"
        )
        about_label = ctk.CTkLabel(
            self.about_win,
            text=about_text,
            font=("Helvetica", 13),
            wraplength=380,
            justify="left",
            text_color="#FFFFFF"
        )
        about_label.pack(padx=20, pady=(20, 5))

        # GitHub link
        github_link = ctk.CTkLabel(
            self.about_win,
            text="GitHub: https://github.com/Robertson-B",
            font=("Helvetica", 13, "underline"),
            text_color="#1a0dab",  # blue
            cursor="hand2"
        )
        github_link.pack(padx=20, pady=(0, 0))
        github_link.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/Robertson-B"))
        # Opens my GitHub profile in a web browser when the link is clicked

        # Email link
        email_link = ctk.CTkLabel(
            self.about_win,
            text="Contact: BitRealmgames@gmail.com",
            font=("Helvetica", 13, "underline"),
            text_color="#1a0dab",  # blue
            cursor="hand2"
        )
        email_link.pack(padx=20, pady=(0, 20))
        email_link.bind("<Button-1>", lambda e: webbrowser.open("mailto:BitRealmgames@gmail.com"))
        # Opens the default email client with my email address when clicked

        self.about_win.attributes("-topmost", True)
        self.about_win.lift()

    def generate_secure_password(self):
        #Generate a random, secure password with widely accepted special characters.
        length =  16  # Length of the generated password
        # Safe special characters for most sites
        safe_specials = "!@#$%^&*()-_=+[]{};:,.?/"
        characters = string.ascii_letters + string.digits + safe_specials
        password = "".join(random.choice(characters) for _ in range(length))
        self.password_entry.delete(0, "end")  # Clear the entry field
        self.password_entry.insert(0, password)  # Insert the generated password

    def check_password_strength(self):
        password = self.password_entry.get()

        if not password: #  checks if anything is inputed
            self.result_label.configure(text="No Password Entered", text_color="#FF5252")
            self.feedback_label.configure(text="Please enter a password to check its strength.")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            self.strength_bar.set(0.0)  # Make the bar empty if no password
            if self.secret_theme_on:
                self.strength_bar.configure(progress_color="#504c54")
            else:
                self.strength_bar.configure(progress_color="#989ca4")
            return
        
        # Easter egg for specific passwords
        elif password.lower() in ["fong", "fongy", "mrfong"]:
            self.result_label.configure(text="Terrible", text_color="#FF5252")  # Red for bad passwords
            self.feedback_label.configure(text="That's a crap password Fong! Try something more original!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")  # Clear pwned count
            return
        elif password.lower() == "upupdowndownleftrightleftrightba": # Secret code. I wonder where else this pops up?
            self.result_label.configure(text="Easter Egg!", text_color="#FFC107")
            self.feedback_label.configure(text="Konami Code detected! Unfortunately, no extra lives here.")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        elif password.lower() == "nevergonnagiveyouup": # Lol
            self.result_label.configure(text="Rickrolled!", text_color="#FFC107")
            self.feedback_label.configure(text="🎵 Never gonna let you down... but this password will!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            webbrowser.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ") # Opens Rick Astley's "Never Gonna Give You Up" music video
            return
        elif password.lower() in ["bitrealm", "bitrealmgames", "robertson", "brobertson", "bean", "ben","benjamin"]:
            self.result_label.configure(text="Imposter!", text_color="#FFC107")
            self.feedback_label.configure(text="Trying to impersonate the developer? Nice try!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        elif password.lower() in ["1337", "h4x0r", "leet", "l33t", "hacker", "h4cker"]:
            self.result_label.configure(text="Leet Detected!", text_color="#FFC107")
            self.feedback_label.configure(text="Leet detected! Hack the planet!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        elif password.lower() == "drowssap":
            self.result_label.configure(text="Sneaky!", text_color="#FFC107")
            self.feedback_label.configure(text="Trying to be sneaky? 'password' backwards is still weak!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        # Palindrome password easter egg
        elif password and password.lower() == password.lower()[::-1] and len(password) > 2:
            self.result_label.configure(text="Palindrome!", text_color="#FFC107")
            self.feedback_label.configure(text="Cool, your password is a palindrome!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        elif password.lower() == "maytheforcebewithyou":
            self.result_label.configure(text="Star Wars!", text_color="#FFC107")
            self.feedback_label.configure(text="The Force is strong with you, but not this password.")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        elif password.lower() == "iloveyou3000":
            self.result_label.configure(text="Iron Man!", text_color="#FFC107")
            self.feedback_label.configure(text="Iron Man approves, but hackers do too!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        elif self.is_password_in_github_list(password): # Check against GitHub password list
            self.result_label.configure(text="Common", text_color="#FF5252")
            self.feedback_label.configure(text="This password appears in a public list and is really common. Choose another one!")
            self.time_to_crack_label.configure(text="")
            self.pwned_count_label.configure(text="")
            return
        else:
            # Regular password strength evaluation
            strength, color, feedback, time_to_crack = self.evaluate_password(password)
            self.result_label.configure(text=strength, text_color=color)
            self.feedback_label.configure(text=feedback)
            self.time_to_crack_label.configure(text=f"Estimated time to crack: {time_to_crack}")
            self.pwned_count_label.configure(text="")

            # Pwnedpass check. tries to check if password has been leaked before.
            try:
                pwned_count = pwnedpass.pwned(password)
            except Exception:
                pwned_count = 0
            if pwned_count:
                self.pwned_count_label.configure(
                    text=f"This password has been found {pwned_count:,} times in data breaches!",
                    text_color="#FF5252"  # Red for breached
                )
            else:
                color = COLORS["text_secondary"] if not self.secret_theme_on else "#CCCCCC" # Have to do it this way because you can't use an if statement in a function call.
                self.pwned_count_label.configure(
                    text="This password has not been found in any known data breaches.",
                    text_color=color
                )

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
            entropy = len(password) * math.log2(charset_size) # Fun Maths!
        else:
            entropy = 0

        # Estimate time to crack using logarithms to avoid overflow
        guesses_per_second = Decimal(1e14)  # Assume 100 Trillion guesses per second

        try:
            log_total_guesses = Decimal(entropy)  # Use entropy directly in logarithmic form
            seconds_to_crack = Decimal(2) ** log_total_guesses / guesses_per_second
            # Have to use Decimal for large numbers to avoid overflow issues

            # Heat death of the universe: ~1e100 years in seconds
            heat_death_seconds = Decimal("1e100") * Decimal(31536000)

            if seconds_to_crack > 100 * heat_death_seconds:  # If it takes longer than the heat death of the universe 100 times over
                time_to_crack = "Longer than the heat death of the universe! 100 times over! Probably pretty secure."
            elif seconds_to_crack > heat_death_seconds:
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
            time_to_crack = "Inputted password is too large. Why do you need a password this long? Your breaking python! Try something shorter."
            
        # Determine strength based on harsh entropy thresholds
        if entropy < 36:
            self.strength_bar.set(0.25)
            self.strength_bar.configure(progress_color="#FF5252")
            return "Weak", "#FF5252", " ".join(feedback), time_to_crack  # Red for weak passwords
        elif entropy < 60:
            self.strength_bar.set(0.5)
            self.strength_bar.configure(progress_color="#FFC107")
            return "Moderate", "#FFC107", " ".join(feedback), time_to_crack  # Yellow for moderate passwords
        elif entropy < 120:
            self.strength_bar.set(0.75)
            self.strength_bar.configure(progress_color="#4CAF50")
            return "Strong", "#4CAF50", " ".join(feedback), time_to_crack  # Green for strong passwords
        else:
            self.strength_bar.set(1.0)
            self.strength_bar.configure(progress_color="#66BB6A")
            return "Very Strong", "#66BB6A", "Your password is excellent!", time_to_crack  # Lighter green for very strong passwords

    def copy_password_to_clipboard(self): # Self explanatory
        password = self.password_entry.get()
        self.clipboard_clear()
        self.clipboard_append(password)

    def get_password_list(self): 
        #Download the password list once and cache it locally.
        cache_file = "common_passwords.txt"
        github_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt"

        # Download the passwords file if not cached
        if not os.path.exists(cache_file):
            try:
                with urllib.request.urlopen(github_url) as response, open(cache_file, "wb") as out_file:
                    out_file.write(response.read())
                    # Store file in the current directory
            except Exception as e:
                print(f"Error downloading password list: {e}, check web connection and try again.")
                return None
        return cache_file

    def is_password_in_github_list(self, password):
        # Check if the password is in the cached GitHub list.
        cache_file = self.get_password_list()
        if not cache_file:
            return False  # Could not download or access the file

        try:
            with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if password.strip() == line.strip():
                        return True
        except Exception as e:
            print(f"Error reading cached password list: {e}")
        return False

    def validate_password_input(self, new_value): 
    # Only allow valid characters in the password entry, nothing else
        for c in new_value:
            if c not in ALLOWED_PASSWORD_CHARS:
                return False
        return True

    # Secret buttons also happens to be a fully functional key logger, but i dont really want to know what you type.
    def key_listener(self, event):
        # Map keys to the konami code sequence
        key_map = {
            "Up": "up",
            "Down": "down",
            "Left": "left",
            "Right": "right",
            "b": "b",
            "a": "a"
        }
        # For secret button (Konami code)
        if event.keysym in key_map:
            self.konami_progress += key_map[event.keysym]
            if len(self.konami_progress) > len(self.konami_code):
                self.konami_progress = self.konami_progress[-len(self.konami_code):]
            if self.konami_progress == self.konami_code:
                self.show_hidden_button()
                self.konami_progress = ""
        else:
            self.konami_progress = ""

        # For dev area button
        if event.char.isalnum():
            self.dev_code_progress += event.char.lower() #checks if the inputted button is the next in the series, if not restart the series
            if len(self.dev_code_progress) > len(self.dev_code):
                self.dev_code_progress = self.dev_code_progress[-len(self.dev_code):]
            if self.dev_code_progress == self.dev_code:
                self.show_dev_area_button()
                self.dev_code_progress = ""
        else:
            self.dev_code_progress = ""

        # For snake minigame
        if event.char.isalnum():
            self.minigame_code_progress += event.char.lower()
            if len(self.minigame_code_progress) > len(self.minigame_code):
                self.minigame_code_progress = self.minigame_code_progress[-len(self.minigame_code):]
            if self.minigame_code_progress == self.minigame_code:
                self.launch_snake_minigame()
                self.minigame_code_progress = ""
        else:
            self.minigame_code_progress = ""

    def show_hidden_button(self):
        # Place the hidden button next to the self-destruct button at the bottom right
        self.hidden_button.place(relx=1.0, rely=1.0, anchor="se", x=-470, y=-20)

    def hallidays_egg(self): # A good book, terrible movie tho
        self.result_label.configure(text="🎉 Golden egg Unlocked! 🎉", text_color="#FFD700")
        self.feedback_label.configure(text="You found Halliday's egg! Shame my game company is not as good as his. And i'm not giving it to anyone, let alone you.")
        self.time_to_crack_label.configure(text="")
        self.pwned_count_label.configure(text="")

    def toggle_secret_theme(self, event=None):
        # Toggle a secret dark theme on double-clicking the header
        if not self.secret_theme_on:
            ctk.set_appearance_mode("dark")
            self.header_frame.configure(fg_color="#333333")
            self.header_label.configure(text_color="#FFFFFF")
            self.sub_header_label.configure(text_color="#DDDDDD")
            self.card_frame.configure(fg_color="#444444", border_color="#555555")
            self.password_entry.configure(fg_color="#555555", border_color="#666666", text_color="#FFFFFF")
            self.result_label.configure(text_color="#FFFFFF")
            self.feedback_label.configure(text_color="#CCCCCC")
            self.time_to_crack_label.configure(text_color="#CCCCCC")
            self.pwned_count_label.configure(text_color="#FFCCCC")
            self.check_button.configure(fg_color="#0078D7", hover_color="#005A9E")
            self.generate_button.configure(fg_color="#4CAF50", hover_color="#388E3C")
            self.copy_button.configure(fg_color="#FFA500", hover_color="#CC8400")
            self.secret_theme_on = True
            self.check_password_strength()  # Re-check the password strength to update colors
        else:
            ctk.set_appearance_mode("light")
            self.header_frame.configure(fg_color=COLORS["header"])
            self.header_label.configure(text_color="#FFFFFF")
            self.sub_header_label.configure(text_color=COLORS["text_primary"])
            self.card_frame.configure(fg_color=COLORS["card_bg"], border_color=COLORS["card_border"])
            self.password_entry.configure(fg_color=COLORS["entry_bg"], border_color=COLORS["entry_border"], text_color="#000000")
            self.result_label.configure(text_color=COLORS["text_primary"])
            self.feedback_label.configure(text_color=COLORS["text_secondary"])
            self.time_to_crack_label.configure(text_color=COLORS["text_secondary"])
            self.pwned_count_label.configure(text_color="#FF5252")
            self.check_button.configure(fg_color=COLORS["button"], hover_color=COLORS["button_hover"])
            self.generate_button.configure(fg_color="#4CAF50", hover_color="#388E3C")
            self.copy_button.configure(fg_color="#FFA500", hover_color="#CC8400")
            self.secret_theme_on = False
            self.check_password_strength()  # Re-check the password strength to update colors

    def show_random_joke(self):
        import random
        jokes = [ # programming jokes
            "Why do programmers prefer dark mode?\nBecause light attracts bugs!",
            "A SQL query walks into a bar, walks up to two tables and asks:\n'Can I join you?'",
            "Why do Java developers wear glasses?\nBecause they don't see sharp.",
            "There are 10 types of people in the world:\nThose who understand binary and those who don't.",
            "How many programmers does it take to change a light bulb?\nNone, that's a hardware problem.",
            "I would tell you a UDP joke, but you might not get it.",
            "To understand recursion, you must first understand recursion.",
            "Why was the developer unhappy at their job?\nThey wanted arrays.",
            "What's a programmer's favorite hangout place?\nThe Foo Bar.",
            "Why did the Python programmer have so many friends?\nBecause they were very open-sourced."
        ]
        joke = random.choice(jokes)
        popup = ctk.CTkToplevel(self)
        popup.title("Random Programming Joke")
        popup.geometry("350x160")
        popup.resizable(False, False)
        popup.configure(fg_color=COLORS["window_bg"])
        label = ctk.CTkLabel(popup, text=joke, font=("Helvetica", 13), justify="center", wraplength=320, text_color="#FFFFFF")
        label.pack(expand=True, fill="both", padx=15, pady=15)
        popup.attributes("-topmost", True)
        popup.lift()

    def show_self_destruct_button(self, event=None):
        # Place the self-destruct button at the bottom right, aligned with the other buttons
        self.self_destruct_button.place(relx=1.0, rely=1.0, anchor="se", x=-320, y=-20)

    def self_destruct_sequence(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Self-Destruct Sequence")
        popup.geometry("350x120")
        popup.resizable(False, False)
        popup.configure(fg_color=COLORS["window_bg"])
        label = ctk.CTkLabel(
            popup,
            text="💥 BOOM! The app will now self-destruct! 💥",
            font=("Helvetica", 15, "bold"),
            justify="center",
            text_color="#FF0000"
        )
        label.pack(expand=True, fill="both", padx=15, pady=15)
        popup.attributes("-topmost", True)
        popup.lift()
        self.after(2000, self.destroy)  # Close the app after 2 seconds

    def open_dev_area_quiz(self):
        # List of (question, answer) pairs
        # Quiz to get into dev area
        if hasattr(self, "quiz_popup") and self.quiz_popup.winfo_exists():
            self.quiz_popup.lift()
            self.quiz_popup.attributes("-topmost", True)
            self.quiz_popup.focus_force()
            return

        questions = [
            ("What is the greatest sci-fi book ever written", "dune"),
            ("What game studio made this program", "bitrealm games"),
            ("What is the first name of the developer?", "benjamin"),
            ("What is the answer to life, the universe, and everything?", "42"),
            ("how many easter eggs are in this app?", "too many"),
            ("what is the greatest premier league team of all time?", "tottenham hotspur"),
            ("What is the last name of the developer?", "robertson"),
            ("What is the secret code?", "upupdowndownleftrightleftrightba"),
            ("What is the greatest game ever made?", "horizon forbidden west"),
            ("Who is the greatest software teacher of all time?", "Fong")
        ]
        self.quiz_index = 0
        self.quiz_score = 0
        self.quiz_questions = questions
        self.quiz_popup = ctk.CTkToplevel(self)
        self.quiz_popup.title("Dev Area Security Quiz")
        self.quiz_popup.geometry("400x200")
        self.quiz_popup.resizable(False, False)
        self.quiz_popup.configure(fg_color=COLORS["window_bg"])
        self.quiz_label = ctk.CTkLabel(self.quiz_popup, text=questions[0][0], font=("Helvetica", 13), wraplength=380, text_color= "#FFFFFF")
        self.quiz_label.pack(pady=(20, 10))
        self.quiz_entry = ctk.CTkEntry(self.quiz_popup, font=("Helvetica", 13), text_color= "#000000")
        self.quiz_entry.pack(pady=(0, 10))
        self.quiz_entry.bind("<Return>", self.check_quiz_answer)
        self.quiz_feedback = ctk.CTkLabel(self.quiz_popup, text="", font=("Helvetica", 11), text_color="#FF5252")
        self.quiz_feedback.pack()
        self.quiz_popup.attributes("-topmost", True)
        self.quiz_popup.lift()


    def check_quiz_answer(self, event=None):
        # Check the answer to the current quiz question to see if the person can access
        answer = self.quiz_entry.get()
        correct = self.quiz_questions[self.quiz_index][1]
        if re.sub(r"\s+", "", answer).lower() == re.sub(r"\s+", "", correct).lower(): # Ignore whitespace and case
            self.quiz_score += 1
        self.quiz_index += 1
        if self.quiz_index < len(self.quiz_questions):
            self.quiz_label.configure(text=self.quiz_questions[self.quiz_index][0])
            self.quiz_entry.delete(0, "end")
        else:
            self.quiz_popup.destroy()
            if self.quiz_score == len(self.quiz_questions):
                self.open_dev_area() # must get everything correct
            else:
                popup = ctk.CTkToplevel(self)
                popup.title("Access Denied")
                popup.geometry("300x100")
                label = ctk.CTkLabel(popup, text="You did not answer all questions correctly.", font=("Helvetica", 13), text_color= "#FFFFFF")
                label.pack(expand=True, fill="both", padx=15, pady=15)
                popup.attributes("-topmost", True)
                popup.configure(fg_color=COLORS["window_bg"])
                popup.lift()

    def open_dev_area(self):
        secrets = [ # Stop cheating and looking at the code!
            "Secret passwords:"
            "Konami code: upupdowndownleftrightleftrightba",
            "Rickroll: nevergonnagiveyouup",
            "Palindrome password: any palindrome",
            "Star Wars: maytheforcebewithyou",
            "Iron Man: iloveyou3000",
            "Leet speak: 1337, h4x0r, leet, l33t, hacker, h4cker",
            "sneaky password: drowssap",
            "Imposter: bitrealm, bitrealmgames, robertson, brobertson,\n    bean, ben, benjamin",
            "Fong's passwords: fong, fongy, mrfong\n",
            "Secret buttons:",
            "Random Joke: tiny dot button in bottom right corner",
            "Keep clicking the eye button",
            "Dark mode: double-click the header\n",
            "Secret commands",
            "Halliday's Egg: Up Up Down Down Left Right Left Right B A",
            "Snake Minigame: Type 'snakegame'",
            "Self-Destruct: Escape key\n",
            "Thanks you for using this app!"
        ]
        popup = ctk.CTkToplevel(self)
        popup.title("Developer Area - All Secrets")
        popup.geometry("500x600")
        popup.resizable(False, False)
        popup.configure(fg_color=COLORS["window_bg"])
        label = ctk.CTkLabel(
            popup,
            text="Welcome to the Developer Area! Here are some secrets and easter eggs:\n\n" + "\n".join(f"- {s}" for s in secrets),
            font=("Helvetica", 13),
            justify="left",
            wraplength=480,
            text_color= "#FFFFFF"
        )
        label.pack(expand=True, fill="both", padx=20, pady=20)
        popup.attributes("-topmost", True)
        popup.lift()

    def show_dev_area_button(self, event=None):
        # Place the dev area button at the bottom left
        self.dev_area_button.place(relx=0.0, rely=1.0, anchor="sw", x=20, y=-20)

    def toggle_password_visibility(self):
        self.show_password = not self.show_password
        self.password_entry.configure(show="" if self.show_password else "*")
        # Optionally, update the button text/icon
        self.toggle_button.configure(text=" 🙈" if self.show_password else "     👁️") # Swap between emojies
        self.toggle_clicks += 1

        # Show funny messages at certain click counts
        if self.toggle_clicks == 20:
            self.feedback_label.configure(text="You really like clicking that, huh?")
        elif self.toggle_clicks == 50:
            self.feedback_label.configure(text="It's just an eye button, not a fidget toy!")
        elif self.toggle_clicks == 100:
            self.feedback_label.configure(text="Okay, that's enough. The password isn't that interesting.")
        elif self.toggle_clicks == 150:
            self.feedback_label.configure(text="Achievement unlocked: Button Masher!")
        elif self.toggle_clicks == 1000:
            self.feedback_label.configure(text="Wow, you really like this button! Here's a secret: You can toggle password visibility with it!")
        elif self.toggle_clicks > 150 and self.toggle_clicks % 50 == 0:
            self.feedback_label.configure(text=f"You've clicked {self.toggle_clicks} times. Impressive dedication!")
        


    def launch_snake_minigame(self):
        # fully functional snake
        snake_win = tk.Toplevel(self)
        snake_win.title("🐍 Snake Minigame 🐍")
        snake_win.geometry("320x340")
        snake_win.resizable(False, False)

        canvas = tk.Canvas(snake_win, width=300, height=300, bg="#222831")
        canvas.pack(padx=10, pady=10)

        direction = "Right"
        snake = [(100, 100), (90, 100), (80, 100)]
        food = (random.randrange(0, 30) * 10, random.randrange(0, 30) * 10)
        running = [True]

        def draw():
            canvas.delete("all")
            for x, y in snake:
                canvas.create_rectangle(x, y, x+10, y+10, fill="#4CAF50")
            fx, fy = food
            canvas.create_oval(fx, fy, fx+10, fy+10, fill="#FFC107")
            snake_win.update_idletasks()

        def move():
            if not running[0]:
                return
            nonlocal food, direction
            x, y = snake[0]
            if direction == "Up":
                y -= 10
            elif direction == "Down":
                y += 10
            elif direction == "Left":
                x -= 10
            elif direction == "Right":
                x += 10
            new_head = (x, y)
            if (x < 0 or x >= 300 or y < 0 or y >= 300 or new_head in snake):
                running[0] = False
                canvas.create_text(150, 150, text="Game Over!", fill="#FF5252", font=("Helvetica", 20, "bold"))
                snake_win.after(2000, snake_win.destroy)  # <-- Close after 2 seconds
                return
            snake.insert(0, new_head)
            if new_head == food:
                food = (random.randrange(0, 30) * 10, random.randrange(0, 30) * 10)
            else:
                snake.pop()
            draw()
            snake_win.after(100, move)

        def on_key(event):
            nonlocal direction
            if event.keysym in ["Up", "Down", "Left", "Right"]:
                if (direction, event.keysym) not in [("Up", "Down"), ("Down", "Up"), ("Left", "Right"), ("Right", "Left")]:
                    direction = event.keysym

        snake_win.bind("<Key>", on_key)
        draw()
        move()
        snake_win.focus_set()

if __name__ == "__main__":
    os.system('cls||clear')  # Clear the console even for stupid macs
    print("\u001b[31;1mLook at the GUI, not the console.") # Colours in the console
    print("\u001b[34m\u001b[0m", end="") 
    app = PasswordCheckerApp()
    app.mainloop()
