import subprocess
import sqlite3
import re

# Connessione al database
conn = sqlite3.connect('certificates.db')
cursor = conn.cursor()

# Creazione della tabella
cursor.execute('''CREATE TABLE IF NOT EXISTS certificates
                (domain TEXT, certificate TEXT)''')


# Funzione per ottenere le informazioni dal comando openssl e inserirle nel database
def process_openssl_output(domain, openssl_output):
    certificates = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', openssl_output, re.DOTALL)
    
    for certificate in certificates:
        certificate_with_boundaries = f"-----BEGIN CERTIFICATE-----\n{certificate.strip()}\n-----END CERTIFICATE-----"
        cursor.execute("INSERT INTO certificates VALUES (?, ?)", (domain, certificate_with_boundaries))
        conn.commit()
    
def run_openssl_command(domain):
    try:
        cmd = f"(echo 'QUIT' ; sleep 1) | openssl s_client -connect {domain}:443 -showcerts"
        openssl_output = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        return openssl_output.stdout
    except subprocess.TimeoutExpired:
        print(f"Timeout expired while fetching certificate for domain {domain}")
        return None

with open("domains.txt", 'r') as infile:
    for domain in infile:
        domain = domain.strip()
        openssl_output = run_openssl_command(domain)
        if openssl_output:
            process_openssl_output(domain, openssl_output)

# Chiudi la connessione al database
conn.close()
