import re
import requests

def analyze_headers(from_email, reply_to):
    if reply_to and reply_to != from_email:
        return "Header mismatch detected (From and Reply-To are different)."
    return "Headers look fine."


def analyze_body(email_body):
    # Expanded list of phishing keywords
    phishing_keywords = ["urgent", "verify your account", "click here",  "final warning", "subscription termination", "payment confirmation", "deposit",
    "unprotected", "secure your device", "renew your subscription" "account compromised"]
    suspicious_links = re.findall(r'https?://[^\s]+', email_body)
    issues = []



    for keyword in phishing_keywords:
        if keyword.lower() in email_body.lower():
            issues.append(f"Phishing keyword detected: {keyword}")

    for link in suspicious_links:
        try:
            response = requests.get(link, timeout=3)
            if response.status_code != 200:
                issues.append(f"Suspicious link detected: {link}")
        except:
            issues.append(f"Invalid or suspicious link: {link}")

    return issues


def main():
    print("Email Phishing Detector")
    print("-" * 30)

    from_email = input("Enter the 'From' email address: ")
    reply_to = input("Enter the 'Reply-To' email address (if available): ")
    email_body = input("Paste the email body content: ")

    header_analysis = analyze_headers(from_email, reply_to)
    print("\nHeader Analysis:")
    print(header_analysis)

    print("\nBody Analysis:")
    issues = analyze_body(email_body)
    if issues:
        for issue in issues:
            print(f"- {issue}")
    else:
        print("No suspicious content found.")

if __name__ == "__main__":
    main()
