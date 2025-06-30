import tkinter as tk
from tkinter import messagebox
import re

try:
    import nltk
    from nltk.corpus import words
    nltk.data.find('corpora/words')
except (ImportError, LookupError):
    nltk = None

class PasswordStrengthCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Password Checker")
        self.geometry("400x500")
        self.resizable(False, False)
        self.configure(bg="#f5f7fa") 
        
        self.font_family = ("Segoe UI", 11)
        self.header_font = ("Segoe UI", 16, "bold")
        self.accent_color = "#346cb0"
        self.warning_color = "#d05353" 
        self.success_color = "#3a853e"  
        self.info_color = "#b08350"
        
        self.current_user = None
        
        self.container = tk.Frame(self, bg="#f5f7fa")
        self.container.pack(fill="both", expand=True)
        
        self.frames = {}
        for F in (LoginFrame, CheckerFrame):
            frame = F(parent=self.container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        
        self.show_frame(LoginFrame)

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()

class LoginFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#f5f7fa")
        self.controller = controller
        
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=3)

        self.create_widgets()

    def create_widgets(self):
        title_label = tk.Label(self, text="Secure Login", font=self.controller.header_font, fg=self.controller.accent_color, bg="#f5f7fa")
        title_label.pack(pady=(40, 20))
        
        user_frame = tk.Frame(self, bg="#f5f7fa")
        user_frame.pack(padx=40, pady=10, fill="x")
        user_label = tk.Label(user_frame, text="Username:", font=self.controller.font_family, bg="#f5f7fa")
        user_label.pack(anchor="w")
        self.user_entry = tk.Entry(user_frame, font=self.controller.font_family)
        self.user_entry.pack(fill="x", pady=6)
        
        pass_frame = tk.Frame(self, bg="#f5f7fa")
        pass_frame.pack(padx=40, pady=10, fill="x")
        pass_label = tk.Label(pass_frame, text="Password:", font=self.controller.font_family, bg="#f5f7fa")
        pass_label.pack(anchor="w")
        self.pass_entry = tk.Entry(pass_frame, font=self.controller.font_family, show="*")
        self.pass_entry.pack(fill="x", pady=6)

        login_btn = tk.Button(self, text="Login", font=self.controller.font_family, bg=self.controller.accent_color, fg="white",
                              activebackground="#264978", activeforeground="white", relief="flat", command=self.login)
        login_btn.pack(pady=40, ipadx=20, ipady=8)

        self.user_entry.bind("<Return>", lambda e: self.pass_entry.focus_set())
        self.pass_entry.bind("<Return>", lambda e: self.login())
        
    def login(self):
        username = self.user_entry.get().strip()
        password = self.pass_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter both username and password.")
            return
        self.controller.current_user = username
        self.controller.show_frame(CheckerFrame)

class CheckerFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#f5f7fa")
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        header_frame = tk.Frame(self, bg="#eff3f8", pady=10)
        header_frame.pack(fill="x")
        self.welcome_label = tk.Label(header_frame, text="", font=self.controller.font_family, fg=self.controller.accent_color, bg="#eff3f8")
        self.welcome_label.pack(side="left", padx=20)
        logout_btn = tk.Button(header_frame, text="Logout", font=self.controller.font_family, bg="#d05353", fg="white",
                               activebackground="#a43939", activeforeground="white", relief="flat", command=self.logout)
        logout_btn.pack(side="right", padx=20, ipadx=10, ipady=4)

        instr_label = tk.Label(self, text="Enter a password to evaluate its strength:", font=self.controller.font_family, bg="#f5f7fa")
        instr_label.pack(pady=(30,10))

        pw_frame = tk.Frame(self, bg="#f5f7fa")
        pw_frame.pack(padx=40, pady=0, fill="x")
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(pw_frame, textvariable=self.password_var, font=self.controller.font_family, show="*")
        self.password_entry.pack(side="left", fill="x", expand=True)

        self.show_password = False
        self.toggle_btn = tk.Button(pw_frame, text="Show", font=self.controller.font_family,
                                    relief="flat", bg="#346cb0", fg="white",
                                    activebackground="#264978", activeforeground="white",
                                    command=self.toggle_password)
        self.toggle_btn.pack(side="left", padx=(8,0), ipadx=10)

        eval_btn = tk.Button(self, text="Check Strength", font=self.controller.font_family, bg=self.controller.accent_color, fg="white",
                             activebackground="#264978", activeforeground="white", relief="flat",
                             command=self.evaluate_password)
        eval_btn.pack(pady=24, ipadx=20, ipady=8)

        self.result_label = tk.Label(self, text="", font=(self.controller.font_family[0], 14, "bold"), bg="#f5f7fa")
        self.result_label.pack(pady=(10,4))

        self.suggestion_title = tk.Label(self, text="", font=(self.controller.font_family[0], 12, "underline"), fg=self.controller.accent_color, bg="#f5f7fa")
        self.suggestion_title.pack(pady=(12,2))
        self.suggestion_text = tk.Label(self, text="", font=self.controller.font_family, fg="#333333", wraplength=320, justify="left", bg="#f5f7fa")
        self.suggestion_text.pack(padx=30)
        
    def toggle_password(self):
        if self.show_password:
            self.password_entry.config(show="*")
            self.toggle_btn.config(text="Show")
            self.show_password = False
        else:
            self.password_entry.config(show="")
            self.toggle_btn.config(text="Hide")
            self.show_password = True
            
    def logout(self):
        self.controller.current_user = None
        self.password_var.set("")
        self.result_label.config(text="", fg="black")
        self.suggestion_title.config(text="")
        self.suggestion_text.config(text="")
        self.controller.show_frame(LoginFrame)
        
    def evaluate_password(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showwarning("Input Required", "Please enter a password to check.")
            return
        
        strength, messages = self.check_strength(pwd)
        color = {
            "Strong": self.controller.success_color,
            "Moderate": self.controller.info_color,
            "Weak": self.controller.warning_color
        }.get(strength, "black")
        
        self.result_label.config(text=f"Password Strength: {strength}", fg=color)
        
        if messages:
            self.suggestion_title.config(text="Suggestions to improve your password:")
            self.suggestion_text.config(text="\n".join(messages))
        else:
            self.suggestion_title.config(text="")
            self.suggestion_text.config(text="Good job! Your password looks strong.")

    def check_strength(self, password):
        messages = []
        score = 0

        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            messages.append("- Make your password at least 8 characters long.")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            messages.append("- Add uppercase letters.")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            messages.append("- Add lowercase letters.")
 
        if re.search(r"[0-9]", password):
            score += 1
        else:
            messages.append("- Add digits.")

        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            messages.append("- Add special characters (e.g. !, @, #, $, %).")

        if nltk:
            lowered = password.lower()
            if lowered in words.words():
                messages.append("- Avoid using common dictionary words.")
            else:
                found_words = [w for w in words.words() if len(w) > 3 and w in lowered]
                if found_words:
                    messages.append("- Avoid using common dictionary words or parts of them.")
        else:
            if re.search(r"[a-z]{4,}", password.lower()):
                messages.append("- Avoid using dictionary words.")

        if score >= 6 and not messages:
            return "Strong", []
        elif score >= 4:
            return "Moderate", messages
        else:
            return "Weak", messages

    def tkraise(self, aboveThis=None):
        super().tkraise(aboveThis)
        username = self.controller.current_user or ""
        self.welcome_label.config(text=f"Welcome, {username}")

if __name__ == "__main__":
    app = PasswordStrengthCheckerApp()
    app.mainloop()
