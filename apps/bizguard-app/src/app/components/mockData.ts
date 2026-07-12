export type RiskLevel = "Critical" | "High" | "Medium" | "Safe";

export interface EmailAnalysis {
  id: string;
  subject: string;
  sender: string;
  senderName: string;
  domain: string;
  date: string;
  body: string;
  // Domain analysis
  domainAge: string;
  domainReputation: "Trusted" | "Suspicious" | "Malicious";
  lookalikeDomain: string | null;
  // AI analysis
  urgency: number;
  fear: number;
  credentialTheft: number;
  financialFraud: number;
  authorityImpersonation: number;
  aiSummary: string;
  // Scores
  aiScore: number;
  domainScore: number;
  threatScore: number;
  riskLevel: RiskLevel;
}

export const mockEmails: EmailAnalysis[] = [
  {
    id: "1",
    subject: "URGENT: Your PayPal account has been suspended",
    sender: "security@paypa1-support.com",
    senderName: "PayPal Security",
    domain: "paypa1-support.com",
    date: "2026-06-13T09:14:00Z",
    body: "Dear Customer, your PayPal account has been suspended due to suspicious activity. Please verify your credentials immediately to restore access. Failure to act within 24 hours will result in permanent account closure.",
    domainAge: "4 days",
    domainReputation: "Malicious",
    lookalikeDomain: "paypal.com",
    urgency: 92,
    fear: 88,
    credentialTheft: 95,
    financialFraud: 65,
    authorityImpersonation: 78,
    aiSummary:
      "Classic phishing attempt impersonating PayPal. The sender domain is a typosquat of paypal.com registered 4 days ago. Message uses urgency and fear tactics to steal credentials.",
    aiScore: 90,
    domainScore: 96,
    threatScore: 92,
    riskLevel: "Critical",
  },
  {
    id: "2",
    subject: "Invoice #INV-2026-0847 — Payment Required",
    sender: "billing@micr0soft-invoices.net",
    senderName: "Microsoft Billing",
    domain: "micr0soft-invoices.net",
    date: "2026-06-13T08:32:00Z",
    body: "Please find attached invoice INV-2026-0847 for $1,249.00 due immediately. Click the link below to review and pay your invoice. Late payments incur a 15% penalty.",
    domainAge: "11 days",
    domainReputation: "Malicious",
    lookalikeDomain: "microsoft.com",
    urgency: 70,
    fear: 55,
    credentialTheft: 40,
    financialFraud: 90,
    authorityImpersonation: 82,
    aiSummary:
      "Financial fraud attempt impersonating Microsoft Billing. Domain registered 11 days ago is a clear typosquat of microsoft.com using '0' in place of 'o'.",
    aiScore: 75,
    domainScore: 92,
    threatScore: 80,
    riskLevel: "High",
  },
  {
    id: "3",
    subject: "Your Google Account security alert",
    sender: "no-reply@google-security-login.net",
    senderName: "Google Security",
    domain: "google-security-login.net",
    date: "2026-06-12T17:55:00Z",
    body: "We noticed a sign-in attempt from an unrecognized device. Please verify your identity by clicking the link below. If you do not verify within 1 hour, your account will be locked.",
    domainAge: "23 days",
    domainReputation: "Suspicious",
    lookalikeDomain: "google.com",
    urgency: 85,
    fear: 72,
    credentialTheft: 88,
    financialFraud: 10,
    authorityImpersonation: 90,
    aiSummary:
      "Credential harvesting attack impersonating Google's security team. Heavy use of urgency and authority impersonation. Domain is not affiliated with Google.",
    aiScore: 80,
    domainScore: 74,
    threatScore: 78,
    riskLevel: "High",
  },
  {
    id: "4",
    subject: "Action required: Verify your DocuSign document",
    sender: "dse@docusign-documents.info",
    senderName: "DocuSign",
    domain: "docusign-documents.info",
    date: "2026-06-12T14:20:00Z",
    body: "You have a document waiting for your review and signature. Please sign within 48 hours to avoid expiry.",
    domainAge: "61 days",
    domainReputation: "Suspicious",
    lookalikeDomain: "docusign.com",
    urgency: 55,
    fear: 30,
    credentialTheft: 45,
    financialFraud: 20,
    authorityImpersonation: 50,
    aiSummary:
      "Moderate risk phishing attempt mimicking DocuSign. Domain is not official but uses plausible wording to solicit a click.",
    aiScore: 45,
    domainScore: 60,
    threatScore: 50,
    riskLevel: "Medium",
  },
  {
    id: "5",
    subject: "Q2 Team Meeting — Agenda Attached",
    sender: "hr@acme-corp.com",
    senderName: "HR Department",
    domain: "acme-corp.com",
    date: "2026-06-12T11:00:00Z",
    body: "Hi team, please find the agenda for the Q2 all-hands meeting scheduled for Friday at 10 AM. Looking forward to seeing everyone.",
    domainAge: "6 years",
    domainReputation: "Trusted",
    lookalikeDomain: null,
    urgency: 5,
    fear: 0,
    credentialTheft: 2,
    financialFraud: 0,
    authorityImpersonation: 3,
    aiSummary: "Legitimate internal communication. No phishing indicators detected.",
    aiScore: 3,
    domainScore: 2,
    threatScore: 2,
    riskLevel: "Safe",
  },
  {
    id: "6",
    subject: "Your AWS bill is ready",
    sender: "billing@aws.amazon.com",
    senderName: "Amazon Web Services",
    domain: "aws.amazon.com",
    date: "2026-06-11T20:00:00Z",
    body: "Your June 2026 AWS bill of $342.18 is now available. View your bill in the AWS console.",
    domainAge: "24 years",
    domainReputation: "Trusted",
    lookalikeDomain: null,
    urgency: 8,
    fear: 2,
    credentialTheft: 0,
    financialFraud: 5,
    authorityImpersonation: 4,
    aiSummary: "Legitimate billing notification from Amazon Web Services. No threats detected.",
    aiScore: 4,
    domainScore: 1,
    threatScore: 3,
    riskLevel: "Safe",
  },
  {
    id: "7",
    subject: "CEO — Urgent Wire Transfer Needed",
    sender: "j.harris.ceo@company-exec.net",
    senderName: "James Harris CEO",
    domain: "company-exec.net",
    date: "2026-06-11T15:45:00Z",
    body: "I'm in a meeting and need you to urgently arrange a wire transfer of $24,500 to our new vendor. This is time-sensitive. Handle this confidentially and reply ASAP.",
    domainAge: "3 days",
    domainReputation: "Malicious",
    lookalikeDomain: null,
    urgency: 95,
    fear: 50,
    credentialTheft: 10,
    financialFraud: 98,
    authorityImpersonation: 97,
    aiSummary:
      "Business Email Compromise (BEC) attack impersonating a CEO requesting wire transfer. Extremely high authority impersonation and financial fraud indicators.",
    aiScore: 92,
    domainScore: 94,
    threatScore: 93,
    riskLevel: "Critical",
  },
  {
    id: "8",
    subject: "Lunch tomorrow?",
    sender: "marco@designstudio.co",
    senderName: "Marco Ricci",
    domain: "designstudio.co",
    date: "2026-06-11T12:30:00Z",
    body: "Hey, are you free for lunch tomorrow around 12:30? There's a new Italian place nearby I've been wanting to try.",
    domainAge: "4 years",
    domainReputation: "Trusted",
    lookalikeDomain: null,
    urgency: 10,
    fear: 0,
    credentialTheft: 0,
    financialFraud: 0,
    authorityImpersonation: 0,
    aiSummary: "Casual personal correspondence. No phishing indicators detected.",
    aiScore: 2,
    domainScore: 3,
    threatScore: 2,
    riskLevel: "Safe",
  },
];

export const riskColors: Record<RiskLevel, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Safe: "#22c55e",
};

export const riskBgColors: Record<RiskLevel, string> = {
  Critical: "rgba(239,68,68,0.1)",
  High: "rgba(249,115,22,0.1)",
  Medium: "rgba(234,179,8,0.1)",
  Safe: "rgba(34,197,94,0.1)",
};
