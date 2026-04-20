import re
import string
import random

print(r"""

 __________                                               .___   _________ __                                 __  .__     
\______   \_____    ______ ________  _  _____________  __| _/  /   _____//  |________   ____   ____    _____/  |_|  |__  
 |     ___/\__  \  /  ___//  ___/\ \/ \/ /  _ \_  __ \/ __ |   \_____  \\   __\_  __ \_/ __ \ /    \  / ___\   __\  |  \ 
 |    |     / __ \_\___ \ \___ \  \     (  <_> )  | \/ /_/ |   /        \|  |  |  | \/\  ___/|   |  \/ /_/  >  | |   Y  \
 |____|    (____  /____  >____  >  \/\_/ \____/|__|  \____ |  /_______  /|__|  |__|    \___  >___|  /\___  /|__| |___|  /
                \/     \/     \/                          \/          \/                   \/     \//_____/           \/ 
___.                                                                                                                     
\_ |__ ___.__.                                                                                                           
 | __ <   |  |                                                                                                           
 | \_\ \___  |                                                                                                           
 |___  / ____|                                                                                                           
     \/\/                                                                                                                
 ___________         __________               .__               .___                                                     
/_   \   _  \ ___  __\______   \_____    _____|  |__   ____   __| _/                                                     
 |   /  /_\  \\  \/  /|       _/\__  \  /  ___/  |  \_/ __ \ / __ |                                                      
 |   \  \_/   \>    < |    |   \ / __ \_\___ \|   Y  \  ___// /_/ |                                                      
 |___|\_____  /__/\_ \|____|_  /(____  /____  >___|  /\___  >____ |                                                      
            \/      \/       \/      \/     \/     \/     \/     \/                     
                                 
""")

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football"
}

def check_repeated_chars(password):
    return bool(re.search(r'(.)\1{2,}', password))

def check_sequential(password):
    sequences = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
    lower = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in lower:
                return True
    return False

def estimate_crack_time(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(not c.isalnum() for c in password): charset += 32
    combinations = charset ** len(password)
    guesses_per_second = 1_000_000_000
    seconds = combinations / guesses_per_second
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 3153600000:
        return f"{seconds/31536000:.1f} years"
    else:
        return "centuries"

def analyze_password(password):
    length      = len(password)
    up          = any(c.isupper() for c in password)
    low         = any(c.islower() for c in password)
    num         = any(c.isdigit() for c in password)
    special     = any(not c.isalnum() and not c.isspace() for c in password)
    is_common   = password.lower() in COMMON_PASSWORDS
    repeated    = check_repeated_chars(password)
    sequential  = check_sequential(password)

    rate = 0
    if length >= 8:   rate += 1
    if length >= 12:  rate += 1
    if up:            rate += 1
    if low:           rate += 1
    if num:           rate += 1
    if special:       rate += 1
    if is_common:     rate -= 2
    if repeated:      rate -= 1
    if sequential:    rate -= 1

    rate = max(0, min(rate, 7))

    if rate <= 2:
        score = "Very Weak"
        bar   = "[##-----]"
    elif rate <= 3:
        score = "Weak"
        bar   = "[###----]"
    elif rate <= 4:
        score = "Medium"
        bar   = "[####---]"
    elif rate <= 5:
        score = "Strong"
        bar   = "[#####--]"
    elif rate <= 6:
        score = "Very Strong"
        bar   = "[######-]"
    else:
        score = "Excellent"
        bar   = "[#######]"

    crack_time = estimate_crack_time(password)

    warnings = []
    if is_common:   warnings.append("  [!] This is a commonly used password")
    if repeated:    warnings.append("  [!] Contains repeated characters (e.g. aaa)")
    if sequential:  warnings.append("  [!] Contains sequential patterns (e.g. abc, 123)")
    if length < 8:  warnings.append("  [!] Password is too short (minimum 8 characters)")

    suggestions = []
    if not up:      suggestions.append("  [+] Add uppercase letters")
    if not low:     suggestions.append("  [+] Add lowercase letters")
    if not num:     suggestions.append("  [+] Add numbers")
    if not special: suggestions.append("  [+] Add special characters (!@#$%^&*)")
    if length < 12: suggestions.append("  [+] Use at least 12 characters for better security")

    print("\n" + "=" * 50)
    print("         PASSWORD ANALYSIS REPORT")
    print("=" * 50)
    print(f"  Strength  : {bar} {score}")
    print(f"  Rating    : {rate} / 7")
    print(f"  Length    : {length} characters")
    print("-" * 50)
    print(f"  Uppercase : {'Yes' if up else 'No'}")
    print(f"  Lowercase : {'Yes' if low else 'No'}")
    print(f"  Numbers   : {'Yes' if num else 'No'}")
    print(f"  Special   : {'Yes' if special else 'No'}")
    print("-" * 50)
    print(f"  Common    : {'Yes - DANGEROUS' if is_common else 'No'}")
    print(f"  Repeated  : {'Yes' if repeated else 'No'}")
    print(f"  Sequential: {'Yes' if sequential else 'No'}")
    print("-" * 50)
    print(f"  Est. Crack: {crack_time}")
    print("=" * 50)

    if warnings:
        print("\n  WARNINGS:")
        for w in warnings: print(w)

    if suggestions:
        print("\n  SUGGESTIONS:")
        for s in suggestions: print(s)

    print()
    return rate

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = ''.join(random.choices(chars, k=length))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(not c.isalnum() for c in pwd)):
            return pwd

def generate_wordlist(word, year):
    specials = ["!", "@", "#", "$", "%", "^", "&", "*"]
    variations = [
        word,
        word + "123",
        word + year,
        word.capitalize(),
        word.upper(),
        word.lower(),
        word + "!",
        word + "@",
        word + "#",
        word + "123!",
        word + year + "!",
        word.capitalize() + year,
        word.capitalize() + "123",
        word.capitalize() + year + "!",
        word + "_" + year,
        word + "." + year,
        "!" + word + year,
        word + year + "@",
        word[0].upper() + word[1:] + year + "!@#",
        word * 2 + year,
    ]
    for s in specials:
        variations.append(word + s + year)
        variations.append(word.capitalize() + s)

    filename = f"wordlist_{word}.txt"
    with open(filename, "w") as f:
        for v in set(variations):
            f.write(v + "\n")

    print(f"\n  [+] Wordlist saved to: {filename}")
    print(f"  [+] Total entries    : {len(set(variations))}")

while True:
    password = input("Enter password to check (or press Enter to generate one): ").strip()

    if not password:
        length_input = input("Enter desired password length (default 16): ").strip()
        length = int(length_input) if length_input.isdigit() else 16
        generated = generate_strong_password(length)
        print(f"\n  Generated Password: {generated}\n")
        password = generated

    rate = analyze_password(password)

    print("  OPTIONS:")
    print("  [1] Check another password")
    print("  [2] Generate wordlist")
    print("  [3] Generate a strong password")
    print("  [4] Exit")

    choice = input("\n  Choose an option: ").strip()

    if choice == "1":
        continue
    elif choice == "2":
        word = input("  Enter a base word for the wordlist: ").strip()
        year = input("  Enter a year to include: ").strip()
        if word:
            generate_wordlist(word, year)
        else:
            print("  [!] No word entered, skipping.")
    elif choice == "3":
        length_input = input("  Enter desired password length (default 16): ").strip()
        length = int(length_input) if length_input.isdigit() else 16
        print(f"\n  Generated Password: {generate_strong_password(length)}\n")
    elif choice == "4":
        print("\n  Goodbye!\n")
        break
    else:
        print("  [!] Invalid choice.")
