import customtkinter as ctk

ctk.set_appearance_mode("light")  # Set light mode for white background
ctk.set_default_color_theme("blue")  # You can choose any theme

app = ctk.CTk()
app.title("Blank White Window")
app.geometry("400x300")  # Set window size (width x height)
app.configure(bg="white")  # Ensure background is white

app.mainloop()