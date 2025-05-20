import customtkinter as ctk # Better Tkinter
import os

# Define a modern color palette for my application
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
        self.geometry("800x600")  # Larger window size
        self.configure(bg=COLORS["background"])  # Use modern background color
        
        # Set light mode and custom theme
        ctk.set_appearance_mode("light") # Dark mode looks crap in custom tkinter
        ctk.set_default_color_theme("MoonlitSky.json")  # Use the custom theme for redundancy in case i forgot to set custom colours

        # Create widgets
        self.create_widgets()

    def create_widgets(self):
        # Decorative header
        self.header_frame = ctk.CTkFrame(self, fg_color=COLORS["header"], corner_radius=0)
        self.header_frame.pack(fill="x")

        self.header_label = ctk.CTkLabel(
            self.header_frame,
            text="🔒 Password Strength Checker 🔒",
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

        # Card-like frame for password entry and buttons
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
            #command=self.check_password_strength,
        )
        self.check_button.pack(pady=10)

if __name__ == "__main__":
    os.system('cls||clear')  # Clear the console even for stupid macs
    print("\u001b[31;1mLook at the GUI, not the console.")
    print("\u001b[34m\u001b[0m", end="")
    app = PasswordCheckerApp()
    app.mainloop()