Step-by-Step Instructions to use the Keylogger

DISCLAIMER: This tool is for educational purposes only. Only use it on devices you have explicit permission to monitor. Unauthorized use may be illegal and unethical.

Step 1: Install the required libraries
Open your command prompt or terminal and execute the following command: "pip install pynput"

Step 2: Copy the provided code
Copy the entire code for the Keylogger application (the content of the "Modified Educational Keylogger (Python)" document) into a new Python file. A good name for this file would be "keylogger.py".

Step 3: Open your command prompt or terminal.

Step 4: Navigate to the directory
Navigate to the directory where you saved the "keylogger.py" file using the cd command. For example, if you saved it on your desktop, you might type:
"cd C:\Users\Admin\Desktop\"

Step 5: Run the application
Execute the keylogger by running the following command. Remember to enclose the filename in quotes if it contains spaces:
"python keylogger.py"

Step 6: Observe the console output
Once the application starts, you will see messages in your terminal indicating that the keylogger has started, the log file path, and instructions to press ESC to stop.

Step 7: Keylogging in action
As you type on your keyboard, your key presses will be recorded in the 3keylog_educational.txt file (located in the same directory as your script).

Character Keys: Regular letters, numbers, and symbols will be logged.

Special Keys: Keys like [BACKSPACE], [TAB], [CTRL], [ALT], and arrow keys will be logged in bracketed format.

Enter Key: When you press Enter, a timestamp [YYYY-MM-DD HH:MM:SS] will be logged on a new line.

Window Changes (Windows only): If you switch to a different active application window, the keylogger will log the new window's title, Process ID (PID), and Process Name along with a timestamp.

Step 8: Stop the keylogger
To stop the keylogger, simply press the ESC key on your keyboard. A message indicating that the keylogger has stopped will appear in the console, and the log file will be closed.

Step 9: View the log file
After stopping the keylogger, you can open the 3keylog_educational.txt file using any text editor (like Notepad, VS Code, etc.) to view the recorded key presses and events.
