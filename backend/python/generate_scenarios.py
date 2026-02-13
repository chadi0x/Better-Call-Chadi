import json

def get_base_css():
    return """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 0; color: #333; }
        .container { max-width: 600px; margin: 40px auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .header { padding: 30px 40px; text-align: center; border-bottom: 1px solid #eee; }
        .header img { height: 40px; width: auto; }
        .content { padding: 40px; text-align: left; line-height: 1.6; }
        .btn { display: inline-block; padding: 12px 24px; color: #ffffff; text-decoration: none; border-radius: 4px; font-weight: 600; margin-top: 20px; }
        .footer { background-color: #f9f9f9; padding: 20px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #eee; }
        .link-text { color: #007bff; text-decoration: none; }
    </style>
    """

def get_platform_style(platform):
    styles = {
        "Google": {"color": "#1a73e8", "logo": "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_160x56dp.png"},
        "Microsoft 365": {"color": "#0078d4", "logo": "https://upload.wikimedia.org/wikipedia/commons/9/96/Microsoft_logo_%282012%29.svg"},
        "Instagram": {"color": "#d62976", "logo": "https://upload.wikimedia.org/wikipedia/commons/thumb/e/e7/Instagram_logo_2016.svg/264px-Instagram_logo_2016.svg.png"},
        "Facebook": {"color": "#1877f2", "logo": "https://upload.wikimedia.org/wikipedia/commons/5/51/Facebook_f_logo_%282019%29.svg"},
        "Netflix": {"color": "#e50914", "logo": "https://upload.wikimedia.org/wikipedia/commons/0/08/Netflix_2015_logo.svg"},
        "PayPal": {"color": "#003087", "logo": "https://upload.wikimedia.org/wikipedia/commons/b/b5/PayPal.svg"},
        "Amazon": {"color": "#ff9900", "logo": "https://upload.wikimedia.org/wikipedia/commons/a/a9/Amazon_logo.svg"},
        "Apple": {"color": "#000000", "logo": "https://upload.wikimedia.org/wikipedia/commons/f/fa/Apple_logo_black.svg"},
        "LinkedIn": {"color": "#0a66c2", "logo": "https://upload.wikimedia.org/wikipedia/commons/c/ca/LinkedIn_logo_initials.png"},
        "Twitter/X": {"color": "#000000", "logo": "https://upload.wikimedia.org/wikipedia/commons/c/ce/X_logo_2023.svg"},
        "Snapchat": {"color": "#FFFC00", "text_color": "#000", "logo": "https://upload.wikimedia.org/wikipedia/en/c/c4/Snapchat_logo.svg"},
        "Chase Bank": {"color": "#117aca", "logo": "https://upload.wikimedia.org/wikipedia/commons/d/d6/Chase_Bank_logo_2005.svg"}
    }
    return styles.get(platform, {"color": "#333333", "logo": ""})

def build_template(platform, subject, body_html, btn_text):
    style = get_platform_style(platform)
    logo_html = f'<img src="{style["logo"]}" alt="{platform}">' if style["logo"] else f'<h1 style="color:{style["color"]}">{platform}</h1>'
    
    # Custom tweaks
    btn_style = f'background-color: {style["color"]};'
    if "text_color" in style:
        btn_style += f' color: {style["text_color"]};'
        
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{subject}</title>
    {get_base_css()}
</head>
<body>
    <div class="container">
        <div class="header">
            {logo_html}
        </div>
        <div class="content">
            <h2 style="margin-top:0;">{subject}</h2>
            {body_html}
            <center>
                <a href="{{{{LINK}}}}" class="btn" style="{btn_style}">{btn_text}</a>
            </center>
            <p style="margin-top: 30px; font-size: 13px;">If the button above doesn't work, copy and paste this link into your browser:<br>
            <span style="color: {style["color"]};">{{{{LINK}}}}</span></p>
        </div>
        <div class="footer">
            <p>This message was sent to {{{{TARGET}}}}.</p>
            <p>&copy; {datetime.now().year} {platform}, Inc. All rights reserved.</p>
            <p style="color:#aaa;">Unsubscribe | Privacy Policy</p>
        </div>
    </div>
</body>
</html>"""
    return html

from datetime import datetime

# --- DATABASE DEFINITION ---
data = {
    "Google": {
        "scenarios": [
            {"name": "Security Alert", "subject": "Security alert", "body": "<p>A new sign-in on <b>Windows</b> was detected. We blocked the attempt, but we need you to review your security settings immediately.</p>", "btn": "Check Activity"},
            {"name": "Storage Full", "subject": "Your storage is almost full", "body": "<p>You have used 98% of your storage. You will soon be unable to send or receive emails unless you free up space or purchase additional storage.</p>", "btn": "Get Storage"}
        ]
    },
    "Microsoft 365": {
        "scenarios": [
            {"name": "Password Expiry", "subject": "Action Required: Password Expiry", "body": "<p>Your organization requires you to change your password every 90 days. Your password for <b>{{TARGET}}</b> will expire in 24 hours.</p>", "btn": "Keep Current Password"},
            {"name": "Shared File", "subject": "HR shared a file with you", "body": "<p><b>Human Resources</b> has shared a file with you via OneDrive.</p><p><i>'Q3_Severance_Package.xlsx'</i></p>", "btn": "Open in OneDrive"}
        ]
    },
    "Instagram": {
        "scenarios": [
            {"name": "Copyright Infringement", "subject": "Copyright Violation Detected", "body": "<p>We have detected a copyright violation in one of your recent posts. Your account will be suspended within 24 hours unless you appeal this decision.</p>", "btn": "Appeal Decision"},
            {"name": "Blue Badge", "subject": "You are eligible for verification", "body": "<p>Congratulations! You have been selected for the blue badge verification. Confirm your identity to get verified.</p>", "btn": "Apply Now"}
        ]
    },
    "Netflix": {
        "scenarios": [
            {"name": "Payment Failed", "subject": "Please update your payment details", "body": "<p>We attempted to bill your membership but your payment failed. To avoid service interruption, please update your payment information.</p>", "btn": "Update Payment"}
        ]
    },
    "Amazon": {
        "scenarios": [
            {"name": "Order Confirmation", "subject": "Order Confirmation: Sony 65-inch TV", "body": "<p>Thank you for your order. Your payment of <b>$1,299.99</b> has been processed.</p><p>If you did not authorize this purchase, please contact us immediately.</p>", "btn": "View Order Details"},
            {"name": "Account Locked", "subject": "Your account has been locked", "body": "<p>We detected unusual activity on your account. For your protection, we have temporarily locked it.</p>", "btn": "Unlock Account"}
        ]
    },
    "PayPal": {
        "scenarios": [
            {"name": "Receipt", "subject": "Receipt for your payment to Coinbase", "body": "<p>You sent <b>$450.00 USD</b> to Coinbase Inc.</p><p>Transaction ID: 9X32152342<br>Date: Today</p><p>If you did not authorize this, cancel the transaction below.</p>", "btn": "Cancel Transaction"}
        ]
    },
    "Bank of America": {
        "scenarios": [
            {"name": "Unusual Activity", "subject": "Suspicious Activity Detected", "body": "<p>We declined a transaction of <b>$1,200.00</b> at Best Buy. Was this you?</p>", "btn": "Review Activity"}
        ]
    },
    "Apple": {
        "scenarios": [
            {"name": "iCloud Locked", "subject": "Your Apple ID has been locked", "body": "<p>For your security, we have automatically disabled your Apple ID because of a sign-in attempt from a new device.</p>", "btn": "Unlock Apple ID"},
            {"name": "Purchase Receipt", "subject": "Invoice for your purchase", "body": "<p>You purchased <b>MacBook Pro 14-inch</b> ($1,999.00). If you did not make this purchase, contact support immediately.</p>", "btn": "Cancel Purchase"}
        ]
    },
    "LinkedIn": {
        "scenarios": [
            {"name": "Profile Views", "subject": "You appeared in 12 searches this week", "body": "<p>People are looking for you. See who viewed your profile and found you in search results.</p>", "btn": "See All Views"},
            {"name": "New Job", "subject": "Recruiter from Google sent you a message", "body": "<p>Hi, I came across your profile and I am very impressed with your background...</p>", "btn": "Read Message"}
        ]
    },
    "Twitter/X": {
        "scenarios": [
            {"name": "Shadowban Alert", "subject": "Your account visibility is limited", "body": "<p>We've found that your account violated our rules. Your posts will not be seen by anyone.</p>", "btn": "Appeal Decision"}
        ]
    },
    "Dropbox": {
        "scenarios": [
            {"name": "File Shared", "subject": "DocuSign sent you a file via Dropbox", "body": "<p><b>DocuSign</b> wants to share <i>'Contract_Draft_v2.pdf'</i> with you.</p>", "btn": "View File"}
        ]
    },
    "Zoom": {
        "scenarios": [
            {"name": "Missed Meeting", "subject": "You missed a meeting with CEO", "body": "<p>The meeting 'Q3 Strategy Review' has ended. You can watch the recording below.</p>", "btn": "Watch Recording"}
        ]
    },
    "Slack": {
        "scenarios": [
            {"name": "New Workspace", "subject": "Invitation to join 'Engineering Team'", "body": "<p><b>Chadi</b> has invited you to join the Slack workspace.</p>", "btn": "Join Now"}
        ]
    },
    "GitHub": {
        "scenarios": [
            {"name": "Repo Access", "subject": "@octocat added you to a repository", "body": "<p>You have been granted write access to <b>private-repo/backend-v2</b>.</p>", "btn": "View Repository"}
        ]
    },
    "Adobe": {
        "scenarios": [
            {"name": "Subscription Ending", "subject": "Your Creative Cloud subscription is ending", "body": "<p>We were unable to charge your card ending in 1234. Your access will be revoked in 24 hours.</p>", "btn": "Update Payment"}
        ]
    },
    "Spotify": {
        "scenarios": [
            {"name": "Payment Failed", "subject": "Problem with your payment", "body": "<p>Oops, your payment failed. Update your card to keep listening to Premium.</p>", "btn": "Update Card"}
        ]
    },
    "TikTok": {
        "scenarios": [
            {"name": "Shadowban", "subject": "Your video was removed", "body": "<p>Your recent video was removed for violating our Community Guidelines.</p>", "btn": "View Status"}
        ]
    },
    "Snapchat": {
        "scenarios": [
            {"name": "Login Alert", "subject": "New login from Android Device", "body": "<p>We noticed a login to your account from a new device in <b>Moscow, Russia</b>.</p>", "btn": "Secure Account"}
        ]
    },
    "WhatsApp": {
        "scenarios": [
            {"name": "Backup Issue", "subject": "Backup failed", "body": "<p>Your chat backup to iCloud failed. You may lose your chat history.</p>", "btn": "Retry Backup"}
        ]
    },
    "Discord": {
        "scenarios": [
            {"name": "Nitro Gift", "subject": "You received a Nitro Gift!", "body": "<p>A friend sent you a gift: <b>1 Month Discord Nitro</b>.</p>", "btn": "Accept Gift"}
        ]
    },
    "Coinbase": {
        "scenarios": [
            {"name": "Withdrawal", "subject": "Withdrawal Confirmation: 2.5 BTC", "body": "<p>You requested to withdraw **2.5 BTC** to external wallet 1A1zP1e...</p>", "btn": "Cancel Withdrawal"}
        ]
    },
    "Binance": {
        "scenarios": [
            {"name": "API Key", "subject": "New API Key Created", "body": "<p>A new API key 'AutoTrade_Bot' was created on your account.</p>", "btn": "Disable Key"}
        ]
    },
    "Chase Bank": {
        "scenarios": [
            {"name": "Fraud Alert", "subject": "Suspicious Activity Detected", "body": "<p>Did you spend <b>$200.00</b> at Target just now?</p>", "btn": "No, it wasn't me"}
        ]
    },
    "Wells Fargo": {
        "scenarios": [
            {"name": "Zelle Transfer", "subject": "Zelle Transfer: $500 Sent", "body": "<p>You sent $500.00 to 'John Doe'. Money leaves your account immediately.</p>", "btn": "Dispute Transaction"}
        ]
    },
    "IRS / Government": {
        "scenarios": [
            {"name": "Tax Refund", "subject": "You have a pending tax refund", "body": "<p>We have calculated your tax refund of <b>$1,200.50</b>. Use the portal to claim it.</p>", "btn": "Claim Refund"}
        ]
    },
    "FedEx/DHL": {
        "scenarios": [
            {"name": "Delivery Failed", "subject": "We could not deliver your package", "body": "<p>Driver attempted delivery but no one was home. Reschedule now to avoid return to sender.</p>", "btn": "Reschedule Delivery"}
        ]
    },
    "GitLab": {
        "scenarios": [
            {"name": "Pipeline Failed", "subject": "Pipeline #12345 failed", "body": "<p>Your recent commit to <b>main</b> caused the build pipeline to fail.</p>", "btn": "View Logs"}
        ]
    },
    "Telegram": {
        "scenarios": [
            {"name": "Export Data", "subject": "Export your data request", "body": "<p>We received a request to export your chat history. If this wasn't you, secure your account.</p>", "btn": "Cancel Request"}
        ]
    },
    "Roblox": {
        "scenarios": [
            {"name": "Security Alert", "subject": "Roblox Account Security Alert", "body": "<p>We detected suspicious activity on your account. Please verifying your information to continue playing.</p>", "btn": "Verify Account"}
        ]
    },
    "Steam": {
        "scenarios": [
            {"name": "Trade Offer", "subject": "New Trade Offer Received", "body": "<p>You have a new trade offer from <b>Gamer123</b>. Items: ★ Karambit | Fade.</p>", "btn": "View Offer"}
        ]
    },
    "Twitch": {
        "scenarios": [
            {"name": "Login Code", "subject": "Your Twitch Verification Code", "body": "<p>Your verification code is: <b>829103</b>. Don't share this code with anyone.</p>", "btn": "Login"}
        ]
    }
}

# Fill in the templates
for platform, p_data in data.items():
    for scenario in p_data["scenarios"]:
        scenario["template"] = build_template(platform, scenario["subject"], scenario["body"], scenario["btn"])
        # Remove helper keys to keep JSON clean
        del scenario["body"]
        del scenario["btn"]

# Save
with open("/Users/chadi/Documents/Project Folders/Better Call Chadi/backend/python/phishing_scenarios.json", "w") as f:
    json.dump(data, f, indent=4)

print("Generated phishing_scenarios.json")
