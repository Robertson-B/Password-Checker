import math   # For entropy
import re   # Regular expressions for password checking
from decimal import Decimal   # Allows the program to store massive numbers
import random   # For generating random passwords
import string   # For generating random passwords
import os   # For clearing the console
import urllib.request   # For checking if the password is in a public GitHub list of common passwords
import webbrowser   # For easter eggs
import tkinter as tk   # for secret minigames
import json   # For achievement storage
import time   # For timing password checks
import datetime   # For seeing how degenerate you are with your password checks
import threading # For a cool intro in the terminal

import pwnedpass   # For checking if the password has been pwned in data breaches
import customtkinter as ctk   # Better than tkinter and gooeypie
from terminaltexteffects.effects.effect_blackhole import Blackhole  # For the blackhole effect on the console

# Define a modern color palette for the app
COLORS = {
    # Custom Tkinter requires the american spelling of Colour for elements like fg_color because it is stupid and american
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

ALL_ACHIEVEMENTS = { 
    # Fun acheivements to unlock
    "Egg Hunter": "Get the platinum trophy!",
    "First Check!": "You checked your first password.",
    "Century Checker": "You've checked 100 passwords!",
    "Snake Charmer": "You won the Snake minigame!",
    "Pong Pro": "You won the Pong minigame!",
    "Rickrolled": "Never gonna give rickrolling you up!",
    "Button Masher": "You clicked the eye button 150 times!",
    "Ready player one": "You found Halliday's egg!",
    "Funny guy": "Hope you enjoyed the joke!",
    "Self-Destructed": "You activated the self-destruct sequence!",
    "Dark Mode": "You enabled the secret dark mode!",
    "Tacocat": "Palindromes are cool!",
    "Critic": "Thanks for the feedback",
    "Rejected": "You got rejected by the password checker!",
    "The Chosen One": "He lives.",
    "Distracted": "You distracted the password checker!", 
    "Minesweeper Master": "You won the Minesweeper minigame!",
    "Tic-Tac-Toe Champ": "You won the Tic-Tac-Toe!",
    "Memory Master": "You won the Memory Match minigame!",
    "Curiosity Killed the Cat": "Clicked the joke button 10 times in a row!",
    "Speed Demon": "Checked 5 passwords in under 10 seconds!",
    "Impossible Password": "Entered a password longer than 100 characters!",
    "Night Owl": "Used the app between midnight and 3am!",
    "The Quitter": "Closed the app within 5 seconds of opening it!",
    "Copycat": "Used the Copy to Clipboard button 10 times!",
    "Feedback Loop": "Opened the help window 5 times!",
    "404 Not Found": "Feedback not found!",
    "The Cake is a Lie": "You entered the forbidden Portal password!",
    "Admin": "You found the developer area with all the secrets and easter eggs! ",
}

class PasswordCheckerApp(ctk.CTk):   # One massive class. best way to do it.
    
    
    def __init__(self):
        super().__init__()

        # Configure the window
        self.title("Password Strength Checker")
        self.geometry("800x600") 
        self.resizable(False, False)
        self.configure(bg=COLORS["background"])  
        ctk.set_appearance_mode("light") 
        # Dark mode is for losers
        self.protocol("WM_DELETE_WINDOW", self.on_close) 
        # Handle window close event

        # Create widgets
        self.create_widgets()

        # Varisbles for the key logger to work
        self.konami_progress = ""
        self.konami_code = "upupdowndownleftrightleftrightba"
        self.dev_code_progress = ""
        self.dev_code = "bitrealm"
        self.minigame_code_progress = ""
        self.minigame_code = "snakegame"
        self.pong_code_progress = ""
        self.pong_code = "pingpong"
        self.minesweeper_code_progress = ""
        self.minesweeper_code = "minesweeper"
        self.tictactoe_code_progress = ""
        self.tictactoe_code = "tictactoe"
        self.memorymatch_code_progress = ""
        self.memorymatch_code = "memorymatch"
        self.copy_count = 0
        self.help_open_count = 0

        self.last_check_times = []

        # Bind key events for secret buttons and Easter eggs
        self.bind_all("<Key>", self.key_listener)
        self.bind_all("<Escape>", self.show_self_destruct_button)

        self.secret_theme_on = False
        self.show_password = True
        self.toggle_clicks = 0
        self.last_joke = None
        self.achievements = set()
        self.password_checks = 0
        self.joke_streak = 0
        self.start_time = time.time()
        
        self.load_progress() # Load achivement progress 


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
        self.about_button.place(relx=1.0, rely=1.0, anchor="se", x=-170, y=-20)  

        # Hidden button (not packed by default) for halliday's egg
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

        # Secret colour swap button in the header
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
            text=" 🙈",
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
        self.toggle_button.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-70)

        # Achievements button 
        self.achievements_button = ctk.CTkButton(
            self,
            text="Achievements",
            font=("Helvetica", 14),
            fg_color="#888888",
            hover_color="#555555",
            corner_radius=10,
            border_width=2,
            border_color=COLORS["button_border"],
            command=self.show_achievements,
        )
        self.achievements_button.place(relx=0.0, rely=1.0, anchor="sw", x=20, y=-20)

        # Developer area button
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
        self.help_open_count += 1
        if self.help_open_count == 5:
            self.unlock_achievement("Feedback Loop", "Opened the help window 5 times!")


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
        email_link.bind(
            "<Button-1>",
            lambda e: (
                self.unlock_achievement("Critic", "Thanks for the feedback"),
                webbrowser.open("mailto:BitRealmgames@gmail.com")
            )
        )
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
            if self.secret_theme_on:
                self.strength_bar.configure(progress_color="#504c54")
            else:
                self.strength_bar.configure(progress_color="#989ca4")
            return
        else:
            # Easter egg for specific passwords
            if password.lower() in ["fong", "fongy", "mrfong"]:
                self.result_label.configure(text="The Chosen One!", text_color="#FF0000")  # Red for bad passwords
                self.feedback_label.configure(text="The legends predicted his arrival!")
                self.unlock_achievement("The Chosen One", "He lives.")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
                return
            elif password.lower() == "upupdowndownleftrightleftrightba":  # Secret code. I wonder where else this pops up?
                self.result_label.configure(text="Easter Egg!", text_color="#FFC107")
                self.feedback_label.configure(text="Konami Code detected! Unfortunately, no extra lives here.")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
                return
            elif password.lower() == "nevergonnagiveyouup":  # Lol
                self.result_label.configure(text="Rickrolled!", text_color="#FFC107")
                self.feedback_label.configure(text="🎵 Never gonna let you down... but this password will!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                self.unlock_achievement("Rickrolled", "Never gonna give rickrolling you up!") 
                webbrowser.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ")  # Opens Rick Astley's "Never Gonna Give You Up" music video
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() == "letmein":
                self.result_label.configure(text="No!", text_color="#FF0707")
                self.feedback_label.configure(text="Get rejected LOL.")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                self.unlock_achievement("Rejected", "You got rejected by the password checker!")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() == "distraction":
                self.result_label.configure(text="Distracted!", text_color="#FF0707")
                self.feedback_label.configure(text="Quick, distract them.")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                self.unlock_achievement("Distracted", "You distracted the password checker!")
                webbrowser.open("https://www.youtube.com/watch?v=XP_ZivuN6iY") 
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() in ["bitrealm", "bitrealmgames", "robertson", "brobertson", "bean", "ben","benjamin"]:
                self.result_label.configure(text="Imposter!", text_color="#FFC107")
                self.feedback_label.configure(text="Trying to impersonate the developer? Nice try!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() in ["1337", "h4x0r", "leet", "l33t", "hacker", "h4cker"]:
                self.result_label.configure(text="Leet Detected!", text_color="#FFC107")
                self.feedback_label.configure(text="Leet detected! Hack the planet!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() == "drowssap":
                self.result_label.configure(text="Sneaky!", text_color="#FFC107")
                self.feedback_label.configure(text="Trying to be sneaky? 'password' backwards is still weak!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() == "404":
                self.result_label.configure(text="404 Not Found!", text_color="#FF5252")
                self.feedback_label.configure(text="This password is not found in our database, but it's still weak!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                self.unlock_achievement("404 Not Found", "Feedback not found!")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password and password.lower() == password.lower()[::-1] and len(password) > 2:   # Palindrome password easter egg
                self.result_label.configure(text="Palindrome!", text_color="#FFC107")
                self.feedback_label.configure(text="Cool, your password is a palindrome!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                self.unlock_achievement("Tacocat", "Palindromes are cool!")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() == "maytheforcebewithyou":
                self.result_label.configure(text="Star Wars!", text_color="#FFC107")
                self.feedback_label.configure(text="The Force is strong with you, but not this password.")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() == "iloveyou3000":
                self.result_label.configure(text="Iron Man!", text_color="#FFC107")
                self.feedback_label.configure(text="Iron Man approves, but hackers do too!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif password.lower() == "thecakeisalie":
                self.result_label.configure(text="The Cake is a Lie!", text_color="#FFC107")
                self.feedback_label.configure(text="You won't find cake here, just weak passwords.")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                self.unlock_achievement("The Cake is a Lie", "You entered the forbidden Portal password!")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
            elif self.is_password_in_github_list(password):  # Check against GitHub password list
                self.result_label.configure(text="Common", text_color="#FF5252")
                self.feedback_label.configure(text="This password appears in a public list and is really common. Choose another one!")
                self.time_to_crack_label.configure(text="")
                self.pwned_count_label.configure(text="")
                if self.secret_theme_on:
                    self.strength_bar.configure(progress_color="#504c54")
                else:
                    self.strength_bar.configure(progress_color="#989ca4")
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
                    color = COLORS["text_secondary"] if not self.secret_theme_on else "#CCCCCC"  # Have to do it this way because you can't use an if statement in a function call.
                    self.pwned_count_label.configure(
                        text="This password has not been found in any known data breaches.",
                        text_color=color
                    )
            self.password_checks += 1
            if self.password_checks == 1:
                self.unlock_achievement("First Check!", "You checked your first password.")
            if self.password_checks == 100:
                self.unlock_achievement("Century Checker", "You've checked 100 passwords!")
            self.save_progress()
            if len(password) > 100:
                self.unlock_achievement("Impossible Password", "Entered a password longer than 100 characters!")
            
            self.last_check_times.append(time.time())
            
            if len(self.last_check_times) > 5:
                self.last_check_times.pop(0)
                
            if len(self.last_check_times) == 5 and self.last_check_times[-1] - self.last_check_times[0] <= 10:
                self.unlock_achievement("Speed Demon", "Checked 5 passwords in under 10 seconds!")
                
            now = datetime.datetime.now()
            if 0 <= now.hour < 3:
                self.unlock_achievement("Night Owl", "Used the app between midnight and 3am!")

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
        guesses_per_second = Decimal(1e14)   # Assume 100 Trillion guesses per second

        try:
            log_total_guesses = Decimal(entropy)   # Use entropy directly in logarithmic form
            seconds_to_crack = Decimal(2) ** log_total_guesses / guesses_per_second
            # Have to use Decimal for large numbers to avoid overflow issues

            # Heat death of the universe: ~1e100 years in seconds
            heat_death_seconds = Decimal("1e100") * Decimal(31536000)

            if seconds_to_crack > 100 * heat_death_seconds:  
                time_to_crack = "Longer than the heat death of the universe! 100 times over!"
            elif seconds_to_crack > heat_death_seconds:
                time_to_crack = "Longer than the heat death of the universe!"
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
        self.copy_count += 1
        if self.copy_count == 10:
            self.unlock_achievement("Copycat", "Used the Copy to Clipboard button 10 times!")


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
            return False  

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

        # For pong minigame
        if event.char.isalnum():
            self.pong_code_progress += event.char.lower()
            if len(self.pong_code_progress) > len(self.pong_code):
                self.pong_code_progress = self.pong_code_progress[-len(self.pong_code):]
            if self.pong_code_progress == self.pong_code:
                self.launch_pong_minigame()
                self.pong_code_progress = ""
        else:
            self.pong_code_progress = ""
        
        # For minesweeper minigame
        if event.char.isalnum():
            self.minesweeper_code_progress += event.char.lower()
            if len(self.minesweeper_code_progress) > len(self.minesweeper_code):
                self.minesweeper_code_progress = self.minesweeper_code_progress[-len(self.minesweeper_code):]
            if self.minesweeper_code_progress == self.minesweeper_code:
                self.launch_minesweeper_minigame()
                self.minesweeper_code_progress = ""
        else:
            self.minesweeper_code_progress = ""
        
        # For tic-tac-toe minigame
        if event.char.isalnum():
            self.tictactoe_code_progress += event.char.lower()
            if len(self.tictactoe_code_progress) > len(self.tictactoe_code):
                self.tictactoe_code_progress = self.tictactoe_code_progress[-len(self.tictactoe_code):]
            if self.tictactoe_code_progress == self.tictactoe_code:
                self.launch_tictactoe_minigame()
                self.tictactoe_code_progress = ""
        else:
            self.tictactoe_code_progress = ""

        # For memory match minigame
        if event.char.isalnum():
            self.memorymatch_code_progress += event.char.lower()
            if len(self.memorymatch_code_progress) > len(self.memorymatch_code):
                self.memorymatch_code_progress = self.memorymatch_code_progress[-len(self.memorymatch_code):]
            if self.memorymatch_code_progress == self.memorymatch_code:
                self.launch_memory_match_minigame()
                self.memorymatch_code_progress = ""
        else:
            self.memorymatch_code_progress = ""


    def show_hidden_button(self):
        # Place the hidden button next to the self-destruct button at the bottom right
        self.hidden_button.place(relx=1.0, rely=1.0, anchor="se", x=-470, y=-20)


    def hallidays_egg(self): # A good book, terrible movie tho
        self.result_label.configure(text="🎉 Golden egg Unlocked! 🎉", text_color="#FFD700")
        self.feedback_label.configure(text="You found Halliday's egg! Shame my game company is not as good as his. And i'm not giving it to anyone, let alone you.")
        self.time_to_crack_label.configure(text="")
        self.pwned_count_label.configure(text="")
        self.unlock_achievement("Ready player one", "You found halliday's egg!")


    def toggle_secret_theme(self, event=None):
        # Toggle a secret dark theme on double-clicking the header
        if not self.secret_theme_on:
            ctk.set_appearance_mode("dark")
            self.unlock_achievement("Dark Mode", "You enabled the secret dark mode!")
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
            self.check_password_strength()   # Re-check the password strength to update colors
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
            self.check_password_strength()   # Re-check the password strength to update colors


    def show_random_joke(self):
        jokes = [ 
            "Why do programmers prefer dark mode?\nBecause light attracts bugs!",
            "A SQL query walks into a bar, walks up to two tables and asks:\n'Can I join you?'",
            "Why do Java developers wear glasses?\nBecause they don't see sharp.",
            "There are 10 types of people in the world:\nThose who understand binary and those who don't.",
            "How many programmers does it take to change a light bulb?\nNone, that's a hardware problem.",
            "I would tell you a UDP joke, but you might not get it.",
            "To understand recursion, you must first understand recursion.",
            "Why was the developer unhappy at their job?\nThey wanted arrays.",
            "What's a programmer's favorite hangout place?\nThe Foo Bar.",
            "Why did the Python programmer have so many friends?\nBecause they were very open-sourced.",
            "Why do programmers hate nature?\nIt has too many bugs.",
            "What do you call a programmer from Finland?\nNerdic.",
            "Where do DBA's keep their dad jokes?\nIn the dad-a-base.",
            "Why did the functional programmer get chucked out of school?\nBecause they ignored all the classes,",
            "How do Linux programs greet each other?\nHow do you sudo?",
            "How long does it take programmers to code a progress bar?\n20 minutes...\nNo, 2 hours...\nNo, 10 minutes...\nNo, 10 days...\nNo, 40 minutes...",
            "Perhaps the real leaky abstractions...\nare the friends we declared along the way.",
        ]
        # Pick a new joke that's not the same as the last one
        joke = random.choice(jokes)
        while joke == self.last_joke and len(jokes) > 1:
            joke = random.choice(jokes)
        self.last_joke = joke

        popup = ctk.CTkToplevel(self)
        popup.title("Random Programming Joke")
        popup.geometry("350x160")
        popup.resizable(False, False)
        popup.configure(fg_color=COLORS["window_bg"])
        label = ctk.CTkLabel(popup, text=joke, font=("Helvetica", 13), justify="center", wraplength=320, text_color="#FFFFFF")
        label.pack(expand=True, fill="both", padx=15, pady=15)
        popup.attributes("-topmost", True)
        popup.lift()
        self.joke_streak += 1
        if self.joke_streak == 10:self.unlock_achievement("Curiosity Killed the Cat", "Clicked the joke button 10 times in a row!")
            
        self.unlock_achievement("Funny guy", "Hope you enjoyed the joke!")


    def show_self_destruct_button(self, event=None):
        # Place the self-destruct button at the bottom right, aligned with the other buttons
        self.self_destruct_button.place(relx=1.0, rely=1.0, anchor="se", x=-320, y=-20)


    def self_destruct_sequence(self):
        # Destroy the window
        popup = ctk.CTkToplevel(self)
        popup.title("Self-Destruct Sequence")
        popup.geometry("350x120")
        popup.resizable(False, False)
        popup.configure(fg_color=COLORS["window_bg"])
        self.unlock_achievement("Self-Destructed", "You activated the self-destruct sequence!")
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
        if re.sub(r"\s+", "", answer).lower() == re.sub(r"\s+", "", correct).lower():   # Ignore whitespace and case
            self.quiz_score += 1
        self.quiz_index += 1
        if self.quiz_index < len(self.quiz_questions):
            self.quiz_label.configure(text=self.quiz_questions[self.quiz_index][0])
            self.quiz_entry.delete(0, "end")
        else:
            self.quiz_popup.destroy()
            if self.quiz_score == len(self.quiz_questions):
                self.open_dev_area()   # must get everything correct
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
        path = os.path.abspath("index.html")  
        webbrowser.open(f"file:///{path.replace(os.sep, '/')}") 
        # Opens and hosts the website for the dev area
        self.unlock_achievement("Admin", "You found the developer area with all the secrets and easter eggs!")
        # Trying to cheat and see all the easter eggs of the program? Well, you have to answer some questions first. 


    def show_dev_area_button(self, event=None):
        # Place the dev area button at the bottom left
        self.dev_area_button.place(relx=0.0, rely=1.0, anchor="sw", x=20, y=-70)


    def toggle_password_visibility(self):
        self.show_password = not self.show_password
        self.password_entry.configure(show="" if self.show_password else "*")
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
            self.unlock_achievement("Button Masher", "You clicked the toggle button 150 times!")
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
                snake_win.after(2000, snake_win.destroy)
                return
            snake.insert(0, new_head)
            if new_head == food:
                food = (random.randrange(0, 30) * 10, random.randrange(0, 30) * 10)
            else:
                snake.pop()
            # WIN CONDITION
            if len(snake) >= 15:
                running[0] = False
                canvas.create_text(150, 150, text="You Win!", fill="#FFD700", font=("Helvetica", 20, "bold"))
                try:
                    self.unlock_achievement("Snake Charmer", "You won the Snake minigame!")
                except Exception:
                    pass
                snake_win.after(2000, snake_win.destroy)
                return
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


    def launch_pong_minigame(self):
        # Fun pong clone
        pong_win = tk.Toplevel(self)
        pong_win.title("🏓 Pong Minigame 🏓")
        pong_win.geometry("500x400")
        pong_win.resizable(False, False)

        canvas = tk.Canvas(pong_win, width=480, height=360, bg="#222831")
        canvas.pack(padx=10, pady=10)

        # Paddle and ball setup
        paddle_height = 60
        paddle_width = 10
        ball_size = 15
        player_y = 150
        ai_y = 150
        ball_speed = 5  # initial speed
        ball_x, ball_y = 240, 180  # Center of the canvas
        ball_dx, ball_dy = ball_speed, ball_speed
        player_score = 0
        ai_score = 0
        running = [True]

        def draw():
            canvas.delete("all")
            # Draw paddles
            canvas.create_rectangle(20, player_y, 20 + paddle_width, player_y + paddle_height, fill="#4CAF50")
            canvas.create_rectangle(450, ai_y, 450 + paddle_width, ai_y + paddle_height, fill="#FFC107")
            # Draw ball
            canvas.create_oval(ball_x, ball_y, ball_x + ball_size, ball_y + ball_size, fill="#FFFFFF")
            # Draw scores
            canvas.create_text(120, 20, text=f"Player: {player_score}", fill="#4CAF50", font=("Helvetica", 14, "bold"))
            canvas.create_text(360, 20, text=f"AI: {ai_score}", fill="#FFC107", font=("Helvetica", 14, "bold"))
            pong_win.update_idletasks()

        def move_ball():
            nonlocal ball_x, ball_y, ball_dx, ball_dy, player_score, ai_score, ai_y, running
            if not running[0]:
                return

            # Move ball
            ball_x += ball_dx
            ball_y += ball_dy

            # Ball collision with top/bottom
            if ball_y <= 0 or ball_y + ball_size >= 360:
                ball_dy = -ball_dy

            # Ball collision with player paddle
            if (20 <= ball_x <= 30 and player_y <= ball_y + ball_size/2 <= player_y + paddle_height):
                ball_dx = abs(ball_dx) *1.05
                ball_dy = ball_dy * 1.05
            # Ball collision with AI paddle
            if (450 <= ball_x + ball_size <= 460 and ai_y <= ball_y + ball_size/2 <= ai_y + paddle_height):
                ball_dx = -abs(ball_dx) *1.05
                ball_dy = ball_dy * 1.05

            # Ball out of bounds (score)
            if ball_x < 0:
                ai_score += 1
                reset_ball()
            elif ball_x > 480:
                player_score += 1
                reset_ball()

            # AI paddle movement (slower)
            if ai_y + paddle_height/2 < ball_y:
                ai_y += 7
            elif ai_y + paddle_height/2 > ball_y:
                ai_y -= 7
            ai_y = max(0, min(360 - paddle_height, ai_y))

            draw()
            if player_score == 5 or ai_score == 5:
                running[0] = False
                winner = "Player" if player_score == 5 else "AI"
                canvas.create_text(240, 180, text=f"{winner} Wins!", fill="#FF5252", font=("Helvetica", 24, "bold"))
                if winner == "Player":
                    try:
                        self.unlock_achievement("Pong Pro", "You won the Pong minigame!")
                    except Exception:
                        pass
                pong_win.after(2000, pong_win.destroy)
                return

            pong_win.after(30, move_ball)

        def reset_ball():
            nonlocal ball_x, ball_y, ball_dx, ball_dy, ball_speed
            ball_x, ball_y = 240, 180  # Center
            ball_speed = 5
            # Randomize direction
            ball_dx = random.choice([-ball_speed, ball_speed])
            ball_dy = random.choice([-ball_speed, ball_speed])
            max_speed = 20
            ball_dx = max(-max_speed, min(ball_dx, max_speed))
            ball_dy = max(-max_speed, min(ball_dy, max_speed))

        def on_key(event):
            nonlocal player_y
            if event.keysym == "Up":
                player_y = max(0, player_y - 20)
            elif event.keysym == "Down":
                player_y = min(360 - paddle_height, player_y + 20)

        pong_win.bind("<Key>", on_key)
        draw()
        move_ball()
        pong_win.focus_set()


    def launch_minesweeper_minigame(self):
        # A fully functional minesweeper clone
        rows, cols, mines = 8, 8, 10

        win = tk.Toplevel(self)
        win.title("💣 Minesweeper 💣")
        win.resizable(False, False)
        frame = tk.Frame(win, bg="#222831")
        frame.pack(padx=10, pady=10)

        # Initialize board
        board = [[0 for _ in range(cols)] for _ in range(rows)]
        revealed = [[False for _ in range(cols)] for _ in range(rows)]
        buttons = [[None for _ in range(cols)] for _ in range(rows)]
        flags = [[False for _ in range(cols)] for _ in range(rows)]

        # Place mines
        mine_positions = set()
        while len(mine_positions) < mines:
            r, c = random.randint(0, rows-1), random.randint(0, cols-1)
            mine_positions.add((r, c))
        for r, c in mine_positions:
            board[r][c] = -1

        # Calculate numbers
        for r in range(rows):
            for c in range(cols):
                if board[r][c] == -1:
                    continue
                count = 0
                for dr in [-1, 0, 1]:
                    for dc in [-1, 0, 1]:
                        nr, nc = r + dr, c + dc
                        if 0 <= nr < rows and 0 <= nc < cols and board[nr][nc] == -1:
                            count += 1
                board[r][c] = count

        def reveal(r, c):
            if revealed[r][c] or flags[r][c]:
                return
            revealed[r][c] = True
            btn = buttons[r][c]
            if board[r][c] == -1:
                btn.config(text="💣", bg="#FF5252", disabledforeground="#000")
                for (mr, mc) in mine_positions:
                    buttons[mr][mc].config(text="💣", bg="#FF5252", disabledforeground="#000")
                win.title("Game Over!")
                for row in buttons:
                    for b in row:
                        b.config(state="disabled")
                win.after(3000, win.destroy)
                return
            btn.config(relief="sunken", state="disabled", bg="#444", text=str(board[r][c]) if board[r][c] > 0 else "", disabledforeground="#FFD700")
            if board[r][c] == 0:
                for dr in [-1, 0, 1]:
                    for dc in [-1, 0, 1]:
                        nr, nc = r + dr, c + dc
                        if 0 <= nr < rows and 0 <= nc < cols:
                            reveal(nr, nc)
            check_win()

        def flag(r, c):
            if revealed[r][c]:
                return
            flags[r][c] = not flags[r][c]
            btn = buttons[r][c]
            btn.config(text="🚩" if flags[r][c] else "")

        def on_click(r, c, event):
            if event.num == 1:  # Left click
                reveal(r, c)
            elif event.num == 3:  # Right click
                flag(r, c)

        def check_win():
            for r in range(rows):
                for c in range(cols):
                    if board[r][c] != -1 and not revealed[r][c]:
                        return
            win.title("You Win!")
            for row in buttons:
                for b in row:
                    b.config(state="disabled")
            try:
                self.unlock_achievement("Minesweeper Master", "You won the Minesweeper minigame!")
            except Exception:
                pass

        # Create buttons
        for r in range(rows):
            for c in range(cols):
                btn = tk.Button(frame, width=3, height=1, font=("Helvetica", 14, "bold"), bg="#393e46", fg="#FFD700", relief="raised")
                btn.grid(row=r, column=c, padx=1, pady=1)
                btn.bind("<Button-1>", lambda e, r=r, c=c: on_click(r, c, e))
                btn.bind("<Button-3>", lambda e, r=r, c=c: on_click(r, c, e))
                buttons[r][c] = btn

        # --- Uncover some safe tiles at the start ---
        safe_to_reveal = []
        for r in range(rows):
            for c in range(cols):
                if board[r][c] != -1:
                    safe_to_reveal.append((r, c))
        random.shuffle(safe_to_reveal)
        revealed_count = 0
        for r, c in safe_to_reveal:
            if revealed_count >= 5:
                break
            if not revealed[r][c]:
                reveal(r, c)
                revealed_count += 1
        win.focus_set()
        win.grab_set()


    def launch_tictactoe_minigame(self):
        # A simple Tic-Tac-Toe game against a random AI
        win = tk.Toplevel(self)
        win.title("Tic-Tac-Toe")
        win.resizable(False, False)
        frame = tk.Frame(win, bg="#222831")
        frame.pack(padx=10, pady=10)

        board = [["" for _ in range(3)] for _ in range(3)]
        buttons = [[None for _ in range(3)] for _ in range(3)]
        player = ["X"]  # Player always starts

        def check_winner():
            # Rows, columns, diagonals
            lines = board + [list(col) for col in zip(*board)]
            lines.append([board[i][i] for i in range(3)])
            lines.append([board[i][2-i] for i in range(3)])
            for line in lines:
                if line == ["X"]*3:
                    return "Player"
                if line == ["O"]*3:
                    return "AI"
            if all(board[r][c] for r in range(3) for c in range(3)):
                return "Draw"
            return None

        def ai_move():
            empty = [(r, c) for r in range(3) for c in range(3) if not board[r][c]]
            if not empty:
                return
            r, c = random.choice(empty)
            board[r][c] = "O"
            buttons[r][c].config(text="O", state="disabled", disabledforeground="#FF5252")
            winner = check_winner()
            if winner:
                end_game(winner)

        def on_click(r, c):
            if board[r][c]:
                return
            board[r][c] = "X"
            buttons[r][c].config(text="X", state="disabled", disabledforeground="#4CAF50")
            winner = check_winner()
            if winner:
                end_game(winner)
                return
            ai_move()
            winner = check_winner()
            if winner:
                end_game(winner)

        def end_game(winner):
            for row in buttons:
                for btn in row:
                    btn.config(state="disabled")
            if winner == "Player":
                win.title("You Win!")
                try:
                    self.unlock_achievement("Tic-Tac-Toe Champ", "You won the Tic-Tac-Toe!")
                except Exception:
                    pass
            elif winner == "AI":
                win.title("AI Wins!")
            else:
                win.title("Draw!")

            win.after(2000, win.destroy)

        for r in range(3):
            for c in range(3):
                btn = tk.Button(frame, width=4, height=2, font=("Helvetica", 20, "bold"), bg="#393e46", fg="#FFD700", relief="raised",
                                command=lambda r=r, c=c: on_click(r, c))
                btn.grid(row=r, column=c, padx=2, pady=2)
                buttons[r][c] = btn

        win.focus_set()
        win.grab_set()


    def launch_memory_match_minigame(self):
        # A simple Memory Match game with 8 pairs of cards
        win = tk.Toplevel(self)
        win.title("Memory Match")
        win.resizable(False, False)
        frame = tk.Frame(win, bg="#222831")
        frame.pack(padx=10, pady=10)

        # Setup cards (8 pairs, shuffled)
        symbols = ["🍎", "🍌", "🍇", "🍒", "🍉", "🍋", "🍓", "🍍"]
        cards = symbols * 2
        random.shuffle(cards)

        rows, cols = 4, 4
        buttons = [[None for _ in range(cols)] for _ in range(rows)]
        revealed = [[False for _ in range(cols)] for _ in range(rows)]
        matched = [[False for _ in range(cols)] for _ in range(rows)]
        first = [None]  # [row, col]
        lock = [False]
        matches_found = [0]

        def check_win():
            if matches_found[0] == 8:
                win.title("You Win!")
                try:
                    self.unlock_achievement("Memory Master", "You won the Memory Match minigame!")
                except Exception:
                    pass
                win.after(2000, win.destroy)

        def on_click(r, c):
            if lock[0] or revealed[r][c] or matched[r][c]:
                return
            btn = buttons[r][c]
            btn.config(text=cards[r*cols+c], state="disabled", disabledforeground="#FFD700", bg="#444")
            revealed[r][c] = True
            if first[0] is None:
                first[0] = (r, c)
            else:
                r1, c1 = first[0]
                if cards[r1*cols+c1] == cards[r*cols+c]:
                    matched[r1][c1] = matched[r][c] = True
                    matches_found[0] += 1
                    first[0] = None
                    check_win()
                else:
                    lock[0] = True
                    win.after(800, lambda: hide_cards(r1, c1, r, c))

        def hide_cards(r1, c1, r2, c2):
            buttons[r1][c1].config(text="", state="normal", bg="#393e46")
            buttons[r2][c2].config(text="", state="normal", bg="#393e46")
            revealed[r1][c1] = revealed[r2][c2] = False
            first[0] = None
            lock[0] = False

        # Create buttons
        for r in range(rows):
            for c in range(cols):
                btn = tk.Button(frame, width=4, height=2, font=("Helvetica", 20, "bold"),
                                bg="#393e46", fg="#FFD700", relief="raised",
                                command=lambda r=r, c=c: on_click(r, c))
                btn.grid(row=r, column=c, padx=2, pady=2)
                buttons[r][c] = btn

        win.focus_set()
        win.grab_set()

    def unlock_achievement(self, name, description):
        if name not in self.achievements:
            self.achievements.add(name)
            self.save_progress()
            popup = ctk.CTkToplevel(self)
            popup.title("")  # No title bar text
            popup.geometry("320x80+30+30")  # Width x Height + X + Y (top left)
            popup.overrideredirect(True)  # Remove window decorations
            popup.resizable(False, False)
            popup.configure(fg_color="#222831")  # Steam-like dark background

            # Achievement icon (emoji or image)
            icon = ctk.CTkLabel(
                popup,
                text="🏆",
                font=("Helvetica", 32),
                text_color="#FFD700",
                fg_color="#222831",
                width=60,
                height=60,
            )
            icon.place(x=10, y=10)

            # Achievement text
            text_label = ctk.CTkLabel(
                popup,
                text=f"Achievement Unlocked!\n{name}\n{description}",
                font=("Helvetica", 13, "bold"),
                justify="left",
                text_color="#FFFFFF",
                fg_color="#222831",
                wraplength=220,
            )
            text_label.place(x=70, y=10)

            popup.attributes("-topmost", True)
            popup.lift()
            # Fade out after 2.5 seconds
            popup.after(2500, popup.destroy)
            
            
        # Check for Egg Hunter achievement
        if name != "Egg Hunter":
            all_but_egg_hunter = set(ALL_ACHIEVEMENTS.keys()) - {"Egg Hunter"}
            if all_but_egg_hunter.issubset(self.achievements):
                # Wait 2.5 seconds before showing Egg Hunter
                self.after(2500, lambda: self.unlock_achievement("Egg Hunter", ALL_ACHIEVEMENTS["Egg Hunter"]))

    def show_achievements(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Achievements")
        popup.geometry("420x400")
        popup.resizable(False, False)
        popup.configure(fg_color=COLORS["window_bg"])

        # Scrollable frame for achievements
        frame = ctk.CTkScrollableFrame(popup, fg_color=COLORS["window_bg"], width=400, height=360)
        frame.pack(expand=True, fill="both", padx=10, pady=10)

        for name, desc in ALL_ACHIEVEMENTS.items():
            unlocked = name in self.achievements
            icon = "🏆" if unlocked else "🔒"
            color = "#FFD700" if unlocked else "#888888"
            ach_frame = ctk.CTkFrame(frame, fg_color=COLORS["window_bg"], border_width=0)
            ach_frame.pack(fill="x", pady=4, padx=4)
            icon_label = ctk.CTkLabel(ach_frame, text=icon, font=("Helvetica", 22), text_color=color, width=40)
            icon_label.pack(side="left")
            text_label = ctk.CTkLabel(
                ach_frame,
                text=f"{name}\n{desc}",
                font=("Helvetica", 13, "bold" if unlocked else "normal"),
                text_color=color,
                justify="left",
                wraplength=320,
            )
            text_label.pack(side="left", padx=8)
        popup.attributes("-topmost", True)
        popup.lift()


    def save_progress(self): 
        # Aaves achievement progress between runs to a json file
        data = {
            "achievements": list(self.achievements),
            "password_checks": self.password_checks
        }
        try:
            with open("progress.json", "w") as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Error saving progress: {e}")


    def load_progress(self): # Loads/ creates achievement file
        try:
            with open("progress.json", "r") as f:
                data = json.load(f)
                self.achievements = set(data.get("achievements", []))
                self.password_checks = data.get("password_checks", 0)
        except Exception:
            # No file or error, just start fresh
            self.achievements = set()
            self.password_checks = 0


    def on_close(self):
        if time.time() - self.start_time < 5:
            self.unlock_achievement("The Quitter", "Closed the app within 5 seconds of opening it!")
        self.destroy()

    def play_blackhole_effect(self, stop_blackhole):
        effect = Blackhole("██╗      ██████╗  ██████╗ ██╗  ██╗     █████╗ ████████╗    ████████╗██╗  ██╗███████╗     ██████╗ ██╗   ██╗██╗\n██║     ██╔═══██╗██╔═══██╗██║ ██╔╝    ██╔══██╗╚══██╔══╝    ╚══██╔══╝██║  ██║██╔════╝    ██╔════╝ ██║   ██║██║\n██║     ██║   ██║██║   ██║█████╔╝     ███████║   ██║          ██║   ███████║█████╗      ██║  ███╗██║   ██║██║\n██║     ██║   ██║██║   ██║██╔═██╗     ██╔══██║   ██║          ██║   ██╔══██║██╔══╝      ██║   ██║██║   ██║██║\n███████╗╚██████╔╝╚██████╔╝██║  ██╗    ██║  ██║   ██║          ██║   ██║  ██║███████╗    ╚██████╔╝╚██████╔╝██║\n╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝   ╚═╝          ╚═╝   ╚═╝  ╚═╝╚══════╝     ╚═════╝  ╚═════╝ ╚═╝\n\n© 2024 BitRealm Studios. All right reserved.\nCreated by Benjamin Robertson")
        with effect.terminal_output() as terminal:
            for frame in effect:
                if stop_blackhole.is_set():
                    break
                terminal.print(frame)




if __name__ == "__main__":
    os.system('cls||clear')  # Clear the console even for stupid macs
    stop_blackhole = threading.Event()  # Create an event to signal stopping
    app = PasswordCheckerApp()
    blackhole_thread = threading.Thread(target=app.play_blackhole_effect, args=(stop_blackhole,), daemon=True) # Have to do the threading outside the class to avoid circular imports
    blackhole_thread.start()
    app.mainloop()
    stop_blackhole.set()  # Signal the effect to stop
    blackhole_thread.join(timeout=1)  # Wait briefly for the thread to finish
    os.system('cls||clear')  # Clear the console again after closing the app

