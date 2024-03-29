import ntpath
from pathlib import Path
from tkinter import Tk, Canvas, Button, PhotoImage, Toplevel, Text, Label, filedialog, messagebox
import re
import requests
import threading
import time
import tkinter as tk


OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"C:\Users\33781\Desktop\CyberShield\assets\frame0")

# Ajout d'une étiquette pour afficher les résultats de l'analyse
result_label = None


# ANALYSE URL !!!


def open_link_window2():
    link_window = Toplevel(window)
    link_window.geometry("1200x200")
    link_window.title("SCAN URL")
    link_window.configure(bg="#F0F0F0")  # Couleur de fond de la fenêtre
    icon = Path(r"C:\Users\33781\Desktop\CyberShield\assets\frame0\logo.ico")
    link_window.iconbitmap(icon)

    label = Label(link_window, text="Enter URL to scan", font=("Arial", 14), bg="#F0F0F0")  # Couleur de fond du label
    label.pack(pady=20)

    link_textarea = Text(link_window, width=100, height=3)
    link_textarea.pack()

    submit_button = Button(link_window, text="Analyze", command=lambda: [URL_Analyse(link_textarea.get("1.0", "end-1c")), link_window.destroy()], bg="#4CAF50", fg="white", padx=10, pady=5)
    submit_button.pack(pady=20)

    link_window.mainloop()


def Read_id(response) :
    found = re.search('"id": "(.+?)",', response).group(1) #group(0) will return full matched string, group(1) only the string between
    return found

def URL_Analyse(link) :

    url = "https://www.virustotal.com/api/v3/urls"
    ans = "url="
    ans = ans + link
    payload = ans
    headers = {
        "accept": "application/json",
        "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f",
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, data=payload, headers=headers)
    #print(response.text)
    Analyse(response,2)


def get_results(response,type) :
    if type == 2:
        found = re.search('"harmless":(.+?),', response).group(0) #group(0) donnera le string et ses marqueurs, group(1) envoie uniquement le string entre les marqueurs
        found = found + "\n" + re.search('"malicious":(.+?),', response).group(0)
        found = found + "\n" + re.search('"suspicious":(.+?),', response).group(0)
        found = found + "\n" + re.search('"undetected":(.+?),', response).group(0)
    else:
        found = re.search('"harmless":(.+?),', response).group(0)
        found = found + "\n" + re.search('"malicious":(.+?),', response).group(0)
        found = found + "\n" + re.search('"suspicious":(.+?),', response).group(0)
        found = found + "\n" + re.search('"undetected":(.+?)\n', response).group(0)
    return found

def Analyse(response, type):
    id = Read_id(response.text)
    id_request = "https://www.virustotal.com/api/v3/analyses/"
    id_request = id_request + id

    headers = {
    "accept": "application/json",
    "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f"
    }
    response = requests.get(id_request, headers=headers)

    #print(response.text)
    while verif_queued(response.text)==1:
        time.sleep(1)
        response = requests.get(id_request, headers=headers)

    results = get_results(response.text,type)
    messagebox.showinfo("Result of Analysis ",str(results))


def Analyse2(response, type):
    id = Read_id(response.text)
    id_request = "https://www.virustotal.com/api/v3/analyses/"
    id_request = id_request + id

    headers = {
    "accept": "application/json",
    "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f"
    }

    response = requests.get(id_request, headers=headers)

    #print(response.text)
    while verif_queued(response.text)==1:
        time.sleep(1)
        response = requests.get(id_request, headers=headers)

    results = get_results(response.text, type)

    return results

# ANALYSE FILES !!

def path_leaf(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def File_Analyse(Files) :
    url = "https://www.virustotal.com/api/v3/files"

    files = {
        "file": (path_leaf(Files), open(Files,"rb"), "application/pdf")
    }
    headers = {
    "accept": "application/json",
    "x-apikey": "0804a81061b66b0775a83ea6d2877e465677be0ec9e70a9727965d62a468196f"
    }

    response = requests.post(url, files=files, headers=headers)
    return str(Analyse2(response,1))

def analyser_fichier(file_path):


    url = "https://api.metadefender.com/v4/file/"
    api_key = "b99e1ba51b33444d8ab462ac16ee4e04"

    headers = {
        "apikey": api_key
    }

    a = File_Analyse(file_path)

    try:
        with open(file_path, "rb") as file:
            response = requests.post(url, headers=headers, files={"file": file})

        if response.status_code == 200:
            data_id = response.json().get("data_id")

            if data_id:
                analysis_url = url + data_id
                analysis_result = None

                # Affichage du chargement
                popup = tk.Tk()
                popup.title("Loading...")
                popup.geometry("200x100")

                label_loading = tk.Label(popup, text="Analysis in progress", font=("Arial", 12))
                label_loading.pack(pady=20)

                popup.update()

                while True:
                    analysis_response = requests.get(analysis_url, headers=headers)

                    if analysis_response.status_code == 200:
                        analysis_result = analysis_response.json()

                        if analysis_result.get("scan_results", {}).get("progress_percentage") == 100:
                            break

                        # Affichage du chargement
                        label_loading.config(text="Analysis in progress...")
                        popup.update()  # Mise à jour de l'interface utilisateur
                        time.sleep(0.5)
                        label_loading.config(text="Analysis in progress.")
                        popup.update()
                        time.sleep(0.5)
                        label_loading.config(text="Analysis in progress..")
                        popup.update()
                        time.sleep(0.5)
                        label_loading.config(text="Analysis in progress...")
                        popup.update()
                        time.sleep(0.5)
                    else:
                        popup.destroy()
                        messagebox.showerror("Error",
                                             "Error retrieving scan results. Status code: {}".format(
                                                 analysis_response.status_code))
                        return

                popup.destroy()

                scan_results = analysis_result.get("scan_results")

                if scan_results:
                    scan_all_result = scan_results.get("scan_all_result_a")

                    if scan_all_result == "No Threat Detected":
                        engine_count = len(scan_results["scan_details"])
                        messagebox.showinfo(" Analysis result","According to Metadefender: \nThe file is secure. \nMetadefender use " + str(engine_count) + " antivirus to find this result \n\nAccording to Virus Total : \n" + a)

                    else:
                        messagebox.showinfo("Analysis result","The file is not secure. Scan result :" + str(scan_all_result))
                else:
                    messagebox.showinfo("Analysis result","Unable to get scan results.")
            else:
                messagebox.showinfo("Analysis result","Failed to get the ID of the data to analyze.")
        else:
            messagebox.showinfo("Analysis result","Error calling Metadefender API. Status code:" + str(response.status_code))
    except IOError:
        messagebox.showinfo("Analysis result","Error reading file.")


def verif_queued(response):
     if re.search('"status": "(.+?)",', response).group(1)=="queued":
         return 1
     else :
         return 0

def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)


def analyze_file(filepath):
    # Fonction pour exécuter l'analyse d'un fichier dans un thread séparé
    try:
        threading.Thread(target=analyser_fichier, args=(filepath,), daemon=True).start()
    except Exception as e:
        messagebox.showerror("Error", str(e))


def select_files_to_analyze():
    # Fonction pour sélectionner les fichiers à analyser
    files = filedialog.askopenfilenames()
    if files:
        for filepath in files:
            analyze_file(filepath)

def open_thankyou_window():
    thankyou_window = Toplevel(window)
    thankyou_window.geometry("600x200")
    thankyou_window.title("Thanks")
    icon = Path(r"C:\Users\33781\Desktop\CyberShield\assets\frame0\logo.ico")
    thankyou_window.iconbitmap(icon)

    message_label = Label(thankyou_window, text="Thank you for using CyberShield.", font=("Arial", 16))
    message_label.pack(pady=50)

def soon_window():
    thankyou_window = Toplevel(window)
    thankyou_window.geometry("600x200")
    thankyou_window.title("Soon....")
    icon = Path(r"C:\Users\33781\Desktop\CyberShield\assets\frame0\logo.ico")
    thankyou_window.iconbitmap(icon)

    message_label = Label(thankyou_window, text="Soon ... stay connected", font=("Arial", 16))
    message_label.pack(pady=50)

def use_extension_window():
    thankyou_window = Toplevel(window)
    thankyou_window.geometry("1200x400")
    thankyou_window.title("How to use an extension ?")
    icon = Path(r"C:\Users\33781\Desktop\CyberShield\assets\frame0\logo.ico")
    thankyou_window.iconbitmap(icon)

    message_label = Label(
        thankyou_window,
        text="1. Download the CyberExtension files to your computer.\n"
             "2. Open Google Chrome and go to the Extensions page.\n"
             "3. Enable Developer Mode by toggling the switch at the top of the Extensions page.\n"
             "4. Add the CyberExtension files to your browser:\n"
             "   -  Drag and drop the files directly onto the Extensions page.\n"
             "   -  Click on the Load unpacked button (or similar) and select the CyberExtension files from your computer.\n"
             "5. Once the files are added, the CyberExtension is ready to use in your browser.\n\n"
             "Make sure to follow these steps in order to successfully launch your extension.",
        font=("Arial", 16),
        justify="left"  # Aligns the text to the left
    )
    message_label.pack(pady=50)


window = Tk()

icon_path= Path(r"C:\Users\33781\Desktop\CyberShield\assets\frame0\logo.ico")
window.geometry("880x487")
window.configure(bg="#3F3B3B")
window.title("CyberShield Antivirus")
window.iconbitmap(icon_path)


canvas = Canvas(
    window,
    bg = "#3F3B3B",
    height = 487,
    width = 880,
    bd = 0,
    highlightthickness = 0,
    relief = "ridge"
)

canvas.place(x = 0, y = 0)
canvas.create_text(
    200.0,
    14.0,
    anchor="nw",
    text="CYBERSHIELD",
    fill="#FFFFFF",
    font=("ArimoHebrewSubset Regular", 64 * -1)
)

button_image_1 = PhotoImage(
    file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=soon_window,
    relief="flat"
)
button_1.place(
    x=578.0,
    y=203.0,
    width=276.0,
    height=150.0
)

button_image_2 = PhotoImage(
    file=relative_to_assets("button_2.png"))
button_2 = Button(
    image=button_image_2,
    borderwidth=0,
    highlightthickness=0,
    command=open_link_window2,
    relief="flat"
)
button_2.place(
    x=302.0,
    y=203.0,
    width=276.0,
    height=150.0
)

button_image_3 = PhotoImage(
    file=relative_to_assets("button_3.png"))
button_3 = Button(
    image=button_image_3,
    borderwidth=0,
    highlightthickness=0,
    command=use_extension_window,
    relief="flat"
)
button_3.place(
    x=578.0,
    y=366.0,
    width=276.0,
    height=108.0
)

button_image_4 = PhotoImage(
    file=relative_to_assets("button_4.png"))
button_4 = Button(
    image=button_image_4,
    borderwidth=0,
    highlightthickness=0,
    command=select_files_to_analyze,
    relief="flat"
)
button_4.place(
    x=26.0,
    y=203.0,
    width=276.0,
    height=150.0
)

canvas.create_rectangle(
    128.0,
    86.96963500976562,
    728.9999389648438,
    92.0,
    fill="#696666",
    outline="")

canvas.create_text(
    128.0,
    100.0,
    anchor="nw",
    text="Defend Your Digital Realm with CyberShield: Unyielding Protection Against Ransomware!",
    fill="#FFFFFF",
    font=("ArefRuqaaInk Regular", 16 * -1)
)

button_image_5 = PhotoImage(
    file=relative_to_assets("button_5.png"))
button_5 = Button(
    image=button_image_5,
    borderwidth=0,
    highlightthickness=0,
    command=open_thankyou_window,
    relief="flat"
)
button_5.place(
    x=26.0,
    y=366.0,
    width=552.0,
    height=108.0
)

image_image_1 = PhotoImage(
    file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(
    76.0,
    73.0,
    image=image_image_1
)
window.resizable(False, False)
window.mainloop()

