import tkinter as tk
from tkinter import scrolledtext, messagebox
from mnemonic import Mnemonic
from eth_account import Account
import bip32utils
import secrets
from hashlib import sha256
import requests
import time
from threading import Thread

BIP39_WORDLIST_FILE = "bip39_wordlist.txt"
RUNNING = True

# Charger la liste de mots BIP39
def load_bip39_wordlist(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return [word.strip() for word in file.readlines()]

# Générer une entropie valide
def generate_entropy(entropy_bits=128):
    if entropy_bits not in [128, 160, 192, 224, 256]:
        raise ValueError("Le nombre de bits d'entropie doit être l'un de [128, 160, 192, 224, 256].")
    return secrets.token_bytes(entropy_bits // 8)

# Convertir l'entropie en phrase mnémonique
def entropy_to_mnemonic(entropy, wordlist):
    entropy_bits = bin(int.from_bytes(entropy, byteorder="big"))[2:].zfill(len(entropy) * 8)
    checksum_bits = bin(int(sha256(entropy).hexdigest(), 16))[2:].zfill(256)[: len(entropy) * 8 // 32]
    full_bits = entropy_bits + checksum_bits
    return " ".join([wordlist[int(full_bits[i:i + 11], 2)] for i in range(0, len(full_bits), 11)])

# Générer une phrase mnémonique
def generate_mnemonic_phrase():
    wordlist = load_bip39_wordlist(BIP39_WORDLIST_FILE)
    entropy = generate_entropy()
    return entropy_to_mnemonic(entropy, wordlist)

# Obtenir le solde Ethereum
def get_eth_balance(address, api_key):
    try:
        url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
        response = requests.get(url, timeout=10)
        data = response.json()
        if data["status"] == "1":
            wei_balance = int(data["result"])
            return wei_balance / (10 ** 18)
    except Exception as e:
        print(f"Erreur lors de la récupération du solde Ethereum : {e}")
    return 0.0

# Obtenir le solde Bitcoin
def get_btc_balance(address):
    try:
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
        response = requests.get(url, timeout=10)
        data = response.json()
        if 'final_balance' in data:
            return data['final_balance'] / (10 ** 8)
    except Exception as e:
        print(f"Erreur lors de la récupération du solde Bitcoin : {e}")
    return 0.0

# Générer une adresse Bitcoin
def generate_btc_address(seed_phrase):
    seed = Mnemonic("english").to_seed(seed_phrase)
    root_key = bip32utils.BIP32Key.fromEntropy(seed)
    child_key = root_key.ChildKey(0).ChildKey(0)
    return child_key.Address()

# Lancer la génération de wallets
def start_generation(api_key, result_display):
    global RUNNING

    if not api_key.strip():
        messagebox.showwarning("Clé API manquante", "Veuillez entrer une clé API valide.")
        return

    def run():
        global RUNNING
        while RUNNING:
            try:
                seed_phrase = generate_mnemonic_phrase()
                Account.enable_unaudited_hdwallet_features()
                eth_account = Account.from_mnemonic(seed_phrase)
                eth_address = eth_account.address
                btc_address = generate_btc_address(seed_phrase)

                eth_balance = get_eth_balance(eth_address, api_key)
                btc_balance = get_btc_balance(btc_address)

                result_display.insert(tk.END, f"Seed Phrase: {seed_phrase}\n")
                result_display.insert(tk.END, f"Adresse Ethereum : {eth_address}\nSolde Ethereum : {eth_balance:.6f} ETH\n")
                result_display.insert(tk.END, f"Adresse Bitcoin : {btc_address}\nSolde Bitcoin : {btc_balance:.6f} BTC\n")
                result_display.insert(tk.END, "-" * 80 + "\n")

                if eth_balance > 0 or btc_balance > 0:
                    with open("phrases.txt", "a", encoding="utf-8") as file:
                        file.write(f"Seed Phrase: {seed_phrase}\n")
                        file.write(f"ETH Address: {eth_address} - Balance: {eth_balance:.6f} ETH\n")
                        file.write(f"BTC Address: {btc_address} - Balance: {btc_balance:.6f} BTC\n\n")

                result_display.see(tk.END)
                time.sleep(0.5)

            except Exception as e:
                print(f"Erreur : {e}")

    Thread(target=run, daemon=True).start()

# Arrêter la génération
def stop_generation():
    global RUNNING
    RUNNING = False

# Configuration de l'application
def create_app():
    app = tk.Tk()
    app.title("Wallet Finder by krdkstore")
    app.geometry("800x700")
    app.resizable(True, True)

    api_key_frame = tk.Frame(app)
    api_key_frame.pack(pady=10)

    tk.Label(api_key_frame, text="API:", font=("Arial", 12)).grid(row=0, column=0, padx=5)
    api_key_entry = tk.Entry(api_key_frame, width=50, font=("Arial", 10))
    api_key_entry.grid(row=0, column=1, padx=5)

    btn_start = tk.Button(
        app, text="Lancer", 
        font=("Arial", 12), bg="#28A745", fg="white", padx=10, pady=5,
        command=lambda: start_generation(api_key_entry.get(), result_display)
    )
    btn_start.pack(pady=10)

    btn_stop = tk.Button(
        app, text="Arreter", 
        font=("Arial", 12), bg="#DC3545", fg="white", padx=10, pady=5,
        command=stop_generation
    )
    btn_stop.pack(pady=10)

    result_display = scrolledtext.ScrolledText(app, wrap=tk.WORD, width=80, height=30, font=("Courier New", 10))
    result_display.pack(pady=10, padx=10)

    label = tk.Label(app, text="telegram : @krdkstore", font=("Arial", 12), anchor="w")
    label.place(x=10, rely=1.0, anchor="sw")

    return app

if __name__ == "__main__":
    app = create_app()
    app.mainloop()
