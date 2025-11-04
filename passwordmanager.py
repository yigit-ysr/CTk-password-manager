from tkinter import *
import customtkinter
from CTkMessagebox import CTkMessagebox
from tkinter.messagebox import askyesno
import os
import sqlite3
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from functools import partial
import base64



class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.key = ""
        self.dbdir = "./db/"
        self.db_path = "./db/records.db"
        self.check_files()
        if self.collect_records():
            placeholder = "Enter the encryption key"
        else:
            placeholder = "Create your key"
        self.title("Password Manager")
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        self.x = (screen_w - 400) // 2
        self.y = (screen_h - 200) // 2
        self.geometry(f"400x200+{self.x}+{self.y}")
        #Placing main tab widgets
        self.resizable(width=False, height=False)
        self.label1 = customtkinter.CTkLabel(self, text="Welcome!", font=("Arial", 20))
        self.label1.pack(pady=(15, 10))
        self.entry1 = customtkinter.CTkEntry(self, placeholder_text=placeholder, width=165, show="*")
        self.entry1.pack(pady=(0, 10))
        self.insert = customtkinter.CTkButton(self, text="Insert", command=self.check_validity)
        self.insert.pack(pady=(0, 10))
        self.frame1 = customtkinter.CTkFrame(self)
        self.frame1.pack()
        self.btn1 = customtkinter.CTkButton(self.frame1, text="See records", state=DISABLED, command=self.see_records)
        self.btn1.pack(side="left", padx=(0, 5))
        self.btn2 = customtkinter.CTkButton(self.frame1, text="Save new credential", state=DISABLED, command=self.save_new_credential_tab)
        self.btn2.pack(side="left")
        self.label2 = customtkinter.CTkLabel(self, text="❗ If it is first time, decide to your encryption key and enter it.")
        self.label2.pack()

    #Creates database if not exist.
    def create_database(self):
        vt = sqlite3.connect(self.db_path)
        cursor = vt.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY,username TEXT, password TEXT)""")
        vt.commit()
        vt.close()

    #Collects all records from records table.
    def collect_records(self):
        vt = sqlite3.connect(self.db_path)
        cursor = vt.cursor()
        cursor.execute("SELECT * FROM records")
        records = cursor.fetchall()
        vt.close()
        return records

    #This is a function for "Save new credential" button.
    def add_record(self):
        username = self.userentry.get()
        password = self.passentry.get()
        if not (username == "" or password == ""):
            vt = sqlite3.connect(self.db_path)
            cursor = vt.cursor()
            cursor.execute("INSERT INTO records(username, password) VALUES(?, ?)", (self.encrypt(username, self.key), self.encrypt(password, self.key)))
            vt.commit()
            vt.close()
            CTkMessagebox(title="Success", message="Your credentials saved.", icon="check")
            self.userentry.delete(0, END)
            self.passentry.delete(0, END)
        else:
            CTkMessagebox(title="", message="Please enter your credentials.", icon="cancel")

    #This is a function for Update buttons.
    def update_record(self, ent1, ent2, ids):
        vt = sqlite3.connect(self.db_path)
        cs = vt.cursor()
        cs.execute("UPDATE records SET username=?, password=? WHERE id=?", (self.encrypt(ent1.get(), self.key), self.encrypt(ent2.get(), self.key),ids))
        vt.commit()
        vt.close()
        CTkMessagebox(title="Success", message="Your credentials saved.", icon="check")

    #Checks the record.db file before the main tab appears.
    def check_files(self):
        if not os.path.exists(self.db_path):
            os.makedirs(self.dbdir, exist_ok=True)
            self.create_database()

    def check_validity(self):
        #Checks null value.
        if self.entry1.get() == "":
            CTkMessagebox(title="Information", message="Please enter a key.")
            return
        self.key = self.entry1.get()
        recs = self.collect_records()
        if not recs:
            self.key = self.entry1.get()
            self.insert.configure(state=DISABLED)
            self.btn1.configure(state=NORMAL)
            self.btn2.configure(state=NORMAL)
            self.entry1.configure(state=DISABLED)
        else:
            #Tries decrypt all records. If there is an error, Program shows "This key is not correct" message.
            errors = 0
            for i in recs:
                for m in i[1:]:
                    try:
                        self.decrypt(m, self.key)
                    except ValueError:
                        errors += 1
            if errors>0:
                CTkMessagebox(title="Error", message="This key is not correct!", icon="cancel")
            else:
                self.label2.configure(text="Key is correct!")
                self.key = self.entry1.get()
                self.insert.configure(state=DISABLED)
                self.btn1.configure(state=NORMAL)
                self.btn2.configure(state=NORMAL)
                self.entry1.configure(state=DISABLED)
    #User can see all records that saved before and update or delete records.
    def see_records(self):
        #If there are records in the database, the “See Records” window opens. If not, a “There aren’t any records” warning appears.
        if self.collect_records():
            self.tplvl1 = customtkinter.CTkToplevel(self)
            self.tplvl1.attributes("-topmost", True)
            self.tplvl1.geometry(f"400x300+{self.x}+{self.y}")
            self.tplvl1.title("Your passwords")
            self.tplvl1.resizable(width=False, height=False)
            self.scr = customtkinter.CTkScrollableFrame(self.tplvl1)
            for i in self.collect_records():
                fr = customtkinter.CTkFrame(self.scr, width=225)
                ent1 = customtkinter.CTkEntry(fr, width=225)
                ent1.insert("end", self.decrypt(i[1], self.key))
                ent1.pack(pady=(0,5))
                ent2 = customtkinter.CTkEntry(fr, width=225)
                ent2.insert("end", self.decrypt(i[2], self.key))
                ent2.pack(pady=(0,5))
                fr.pack()
                fr1 = customtkinter.CTkFrame(fr, width=225)
                btn1 = customtkinter.CTkButton(fr1, text="Update", command=partial(self.update_record, ent1, ent2, i[0]), width=110)
                btn1.pack(side=LEFT, padx=(0,5))
                btn2 = customtkinter.CTkButton(fr1, text="Delete", width=110, command=partial(self.wdestroy, fr, i[0]))
                btn2.pack(side=LEFT)
                fr1.pack(pady=(0,10))
            self.scr.pack(fill="both", expand="yes")

        else:
            CTkMessagebox(title="Information", message="There isn't any record", icon="info")

    #User can save new record with this tab.
    def save_new_credential_tab(self):
        self.tplvl2 = customtkinter.CTkToplevel(self)
        self.tplvl2.title("Save new credential")
        self.tplvl2.attributes("-topmost", True)
        self.tplvl2.geometry(f"350x150+{self.x}+{self.y}")
        self.tplvl2.resizable(width=False, height=False)
        self.userentry = customtkinter.CTkEntry(self.tplvl2, placeholder_text="username", width=185)
        self.userentry.pack(pady=(20, 10))
        self.passentry = customtkinter.CTkEntry(self.tplvl2, placeholder_text="password", width=185)
        self.passentry.pack(pady=(0, 10))
        self.addbtn = customtkinter.CTkButton(self.tplvl2, text="Add record", command=self.add_record)
        self.addbtn.pack(pady=(0, 10))

    #Function for "delete" buttons.
    def wdestroy(self, widget, idm):
        answer = askyesno(title="Deleting a record", message="Are you sure you want to delete this record?", parent=self.tplvl1)
        if answer:
            vt = sqlite3.connect(self.db_path)
            cs = vt.cursor()
            cs.execute("""DELETE FROM records WHERE id=?""",(idm,))
            vt.commit()
            vt.close()
            widget.pack_forget()

    def encrypt(self, plain_text, password):
        # Generate a random 16-byte salt for key derivation
        salt = get_random_bytes(16)

        # Derive a 256-bit (32-byte) encryption key from the password and salt
        # PBKDF2 applies a key stretching algorithm with 100,000 iterations for security
        key = PBKDF2(password, salt, dkLen=32, count=100_000)

        # Generate a random 16-byte initialization vector (IV) for AES CBC mode
        iv = get_random_bytes(16)

        # Create a new AES cipher object in CBC (Cipher Block Chaining) mode
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the plaintext to make its length a multiple of 16 bytes (AES block size)
        padded_text = pad(plain_text.encode(), 16)

        # Encrypt the padded plaintext using the AES cipher
        ciphertext = cipher.encrypt(padded_text)

        # Concatenate salt, IV, and ciphertext into a single byte string
        encrypted_data = salt + iv + ciphertext

        # Encode the encrypted data in Base64 to make it safe for storage or transmission
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_text, password):
        # Decode the Base64-encoded encrypted text back into bytes
        encrypted_data = base64.b64decode(encrypted_text)

        # Extract the first 16 bytes as the salt used for key derivation
        salt = encrypted_data[:16]

        # Extract the next 16 bytes as the initialization vector (IV)
        iv = encrypted_data[16:32]

        # The remaining bytes represent the ciphertext
        ciphertext = encrypted_data[32:]

        # Derive the same 256-bit (32-byte) encryption key using the password and salt
        key = PBKDF2(password, salt, dkLen=32, count=100_000)

        # Recreate the AES cipher object in CBC mode with the derived key and IV
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the ciphertext to get the padded plaintext
        padded_plain_text = cipher.decrypt(ciphertext)

        # Remove padding and decode the plaintext bytes back into a string
        return unpad(padded_plain_text, 16).decode()


if __name__ == "__main__":
    app = App()

    app.mainloop()
