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


if __name__ == "__main__":
    os.system('cls||clear')  # Clear the console even for stupid macs
    print("\u001b[31;1mLook at the GUI, not the console.")
    print("\u001b[34m\u001b[0m", end="")
    app = PasswordCheckerApp()
    app.mainloop()