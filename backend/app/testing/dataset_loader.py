"""
PhishNet Dataset Loader
========================
Loads, validates, and splits labeled email datasets for evaluation.

Supports 4 categories:
    A) Clean Legitimate Emails
    B) Known Phishing Emails
    C) Sophisticated Spear Phishing
    D) Adversarial Obfuscated Emails

Enforces strict train/validation/test splits (70/15/15) with no leakage.
"""

import json
import hashlib
import logging
import random
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("phishnet.testing.dataset_loader")


# ═══════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════

class EmailCategory(str, Enum):
    """Email dataset categories."""
    CLEAN_LEGITIMATE = "CLEAN_LEGITIMATE"
    KNOWN_PHISHING = "KNOWN_PHISHING"
    SPEAR_PHISHING = "SPEAR_PHISHING"
    ADVERSARIAL_OBFUSCATED = "ADVERSARIAL_OBFUSCATED"


class GroundTruth(str, Enum):
    """Ground truth labels for email samples."""
    SAFE = "SAFE"
    PHISHING = "PHISHING"
    SUSPICIOUS = "SUSPICIOUS"


@dataclass
class EmailSample:
    """A single labeled email sample for evaluation."""
    id: str
    sender: str
    sender_display_name: str = ""
    subject: str = ""
    body: str = ""
    body_html: str = ""
    links: List[str] = field(default_factory=list)
    attachments: List[Dict[str, str]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    ground_truth: str = "SAFE"  # SAFE | PHISHING | SUSPICIOUS
    category: str = "CLEAN_LEGITIMATE"
    source: str = "synthetic"
    difficulty: str = "easy"  # easy | medium | hard | adversarial
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        """Deterministic hash for deduplication."""
        raw = f"{self.sender}|{self.subject}|{self.body}|{','.join(self.links)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_raw_email_bytes(self) -> bytes:
        """Convert sample to raw email bytes compatible with EnhancedPhishingAnalyzer."""
        headers = self.headers.copy()
        headers.setdefault("From", f"{self.sender_display_name} <{self.sender}>" if self.sender_display_name else self.sender)
        headers.setdefault("To", "test@phishnet.local")
        headers.setdefault("Subject", self.subject)
        headers.setdefault("MIME-Version", "1.0")
        headers.setdefault("Content-Type", "multipart/mixed; boundary=\"PHISHNET_BOUNDARY\"")

        # Build raw email
        lines = []
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("--PHISHNET_BOUNDARY")
        
        if self.body_html:
            lines.append("Content-Type: text/html; charset=\"utf-8\"")
            lines.append("")
            lines.append(self.body_html)
        else:
            lines.append("Content-Type: text/plain; charset=\"utf-8\"")
            lines.append("")
            lines.append(self.body)
        
        # Add attachment stubs
        for att in self.attachments:
            lines.append("--PHISHNET_BOUNDARY")
            filename = att.get("filename", "unknown.bin")
            content_type = att.get("content_type", "application/octet-stream")
            lines.append(f"Content-Type: {content_type}")
            lines.append(f"Content-Disposition: attachment; filename=\"{filename}\"")
            lines.append("Content-Transfer-Encoding: base64")
            lines.append("")
            lines.append(att.get("content_b64", "dGVzdA=="))  # default: "test"

        lines.append("--PHISHNET_BOUNDARY--")
        return "\r\n".join(lines).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EmailSample":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class DatasetSplit:
    """A named split (train/validation/test) of email samples."""
    name: str
    samples: List[EmailSample]
    
    @property
    def size(self) -> int:
        return len(self.samples)
    
    @property
    def phishing_count(self) -> int:
        return sum(1 for s in self.samples if s.ground_truth == GroundTruth.PHISHING.value)
    
    @property
    def safe_count(self) -> int:
        return sum(1 for s in self.samples if s.ground_truth == GroundTruth.SAFE.value)

    @property
    def suspicious_count(self) -> int:
        return sum(1 for s in self.samples if s.ground_truth == GroundTruth.SUSPICIOUS.value)

    def category_breakdown(self) -> Dict[str, int]:
        breakdown: Dict[str, int] = {}
        for s in self.samples:
            breakdown[s.category] = breakdown.get(s.category, 0) + 1
        return breakdown

    def difficulty_breakdown(self) -> Dict[str, int]:
        breakdown: Dict[str, int] = {}
        for s in self.samples:
            breakdown[s.difficulty] = breakdown.get(s.difficulty, 0) + 1
        return breakdown


# ═══════════════════════════════════════════════════════════════
# DATASET LOADER
# ═══════════════════════════════════════════════════════════════

class DatasetLoader:
    """
    Loads, validates, and splits labeled phishing email datasets.
    
    Enforces:
        - No overlap between train/validation/test splits
        - Stratified splitting to maintain class distribution
        - Content hash deduplication
        - Category and difficulty tagging
    """

    DEFAULT_SPLIT_RATIOS = {"train": 0.70, "validation": 0.15, "test": 0.15}

    def __init__(
        self,
        split_ratios: Optional[Dict[str, float]] = None,
        random_seed: int = 42,
    ):
        self.split_ratios = split_ratios or self.DEFAULT_SPLIT_RATIOS
        self.random_seed = random_seed
        self._validate_split_ratios()
        self._all_samples: List[EmailSample] = []
        self._splits: Dict[str, DatasetSplit] = {}
        self._seen_hashes: set = set()

    def _validate_split_ratios(self) -> None:
        total = sum(self.split_ratios.values())
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"Split ratios must sum to 1.0, got {total}")
        required = {"train", "validation", "test"}
        if not required.issubset(self.split_ratios.keys()):
            raise ValueError(f"Split ratios must include {required}")

    # ─── Loading ──────────────────────────────────────────────

    def load_from_json(self, path: str) -> int:
        """Load labeled emails from a JSON file. Returns count loaded."""
        filepath = Path(path)
        if not filepath.exists():
            raise FileNotFoundError(f"Dataset file not found: {path}")
        
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        samples = data if isinstance(data, list) else data.get("samples", data.get("emails", []))
        loaded = 0
        for item in samples:
            sample = EmailSample.from_dict(item)
            if self._add_sample(sample):
                loaded += 1
        
        logger.info(f"Loaded {loaded} samples from {path} ({len(self._all_samples)} total)")
        return loaded

    def load_from_list(self, samples: List[Dict[str, Any]]) -> int:
        """Load labeled emails from a list of dicts. Returns count loaded."""
        loaded = 0
        for item in samples:
            sample = EmailSample.from_dict(item) if isinstance(item, dict) else item
            if self._add_sample(sample):
                loaded += 1
        logger.info(f"Loaded {loaded} samples ({len(self._all_samples)} total)")
        return loaded

    def load_builtin_dataset(self) -> int:
        """
        Load the built-in benchmark dataset with representative samples
        across all 4 categories and difficulty levels.
        """
        samples = self._generate_builtin_samples()
        return self.load_from_list(samples)

    def _add_sample(self, sample: EmailSample) -> bool:
        """Add sample with deduplication. Returns True if added."""
        h = sample.content_hash
        if h in self._seen_hashes:
            logger.debug(f"Duplicate sample skipped: {sample.id}")
            return False
        self._seen_hashes.add(h)
        self._all_samples.append(sample)
        return True

    # ─── Splitting ────────────────────────────────────────────

    def split(self, stratify: bool = True) -> Dict[str, DatasetSplit]:
        """
        Split loaded dataset into train/validation/test.
        
        Args:
            stratify: If True, maintain class distribution across splits.
        
        Returns:
            Dict mapping split name to DatasetSplit.
        """
        if not self._all_samples:
            raise ValueError("No samples loaded. Call load_* first.")

        rng = random.Random(self.random_seed)

        if stratify:
            splits = self._stratified_split(rng)
        else:
            shuffled = list(self._all_samples)
            rng.shuffle(shuffled)
            splits = self._sequential_split(shuffled)

        self._splits = splits
        self._verify_no_leakage()

        for name, ds in splits.items():
            logger.info(
                f"Split '{name}': {ds.size} samples "
                f"(PHISHING={ds.phishing_count}, SAFE={ds.safe_count}, "
                f"SUSPICIOUS={ds.suspicious_count})"
            )

        return splits

    def _stratified_split(self, rng: random.Random) -> Dict[str, DatasetSplit]:
        """Split maintaining class distribution."""
        by_label: Dict[str, List[EmailSample]] = {}
        for s in self._all_samples:
            by_label.setdefault(s.ground_truth, []).append(s)

        split_buckets: Dict[str, List[EmailSample]] = {name: [] for name in self.split_ratios}

        for label, samples in by_label.items():
            rng.shuffle(samples)
            n = len(samples)
            train_end = int(n * self.split_ratios["train"])
            val_end = train_end + int(n * self.split_ratios["validation"])
            
            split_buckets["train"].extend(samples[:train_end])
            split_buckets["validation"].extend(samples[train_end:val_end])
            split_buckets["test"].extend(samples[val_end:])

        return {name: DatasetSplit(name=name, samples=samples) for name, samples in split_buckets.items()}

    def _sequential_split(self, shuffled: List[EmailSample]) -> Dict[str, DatasetSplit]:
        """Simple sequential split without stratification."""
        n = len(shuffled)
        train_end = int(n * self.split_ratios["train"])
        val_end = train_end + int(n * self.split_ratios["validation"])

        return {
            "train": DatasetSplit(name="train", samples=shuffled[:train_end]),
            "validation": DatasetSplit(name="validation", samples=shuffled[train_end:val_end]),
            "test": DatasetSplit(name="test", samples=shuffled[val_end:]),
        }

    def _verify_no_leakage(self) -> None:
        """Ensure no content hash appears in multiple splits."""
        split_hashes: Dict[str, set] = {}
        for name, ds in self._splits.items():
            split_hashes[name] = {s.content_hash for s in ds.samples}

        names = list(split_hashes.keys())
        for i, n1 in enumerate(names):
            for n2 in names[i + 1:]:
                overlap = split_hashes[n1] & split_hashes[n2]
                if overlap:
                    raise RuntimeError(
                        f"DATA LEAKAGE DETECTED: {len(overlap)} samples shared "
                        f"between '{n1}' and '{n2}' splits. Aborting."
                    )
        logger.info("No data leakage detected across splits.")

    # ─── Accessors ────────────────────────────────────────────

    @property
    def train(self) -> DatasetSplit:
        return self._splits["train"]

    @property
    def validation(self) -> DatasetSplit:
        return self._splits["validation"]

    @property
    def test(self) -> DatasetSplit:
        return self._splits["test"]

    @property
    def total_samples(self) -> int:
        return len(self._all_samples)

    def get_split(self, name: str) -> DatasetSplit:
        if name not in self._splits:
            raise KeyError(f"Split '{name}' not found. Available: {list(self._splits.keys())}")
        return self._splits[name]

    def summary(self) -> Dict[str, Any]:
        """Return summary statistics of the loaded dataset."""
        by_category: Dict[str, int] = {}
        by_truth: Dict[str, int] = {}
        by_difficulty: Dict[str, int] = {}
        for s in self._all_samples:
            by_category[s.category] = by_category.get(s.category, 0) + 1
            by_truth[s.ground_truth] = by_truth.get(s.ground_truth, 0) + 1
            by_difficulty[s.difficulty] = by_difficulty.get(s.difficulty, 0) + 1

        return {
            "total_samples": self.total_samples,
            "by_category": by_category,
            "by_ground_truth": by_truth,
            "by_difficulty": by_difficulty,
            "splits": {
                name: {
                    "size": ds.size,
                    "phishing": ds.phishing_count,
                    "safe": ds.safe_count,
                    "suspicious": ds.suspicious_count,
                }
                for name, ds in self._splits.items()
            } if self._splits else {},
        }

    # ─── Export ────────────────────────────────────────────────

    def export_to_json(self, path: str) -> None:
        """Export loaded dataset to JSON."""
        data = {
            "metadata": {
                "total_samples": self.total_samples,
                "split_ratios": self.split_ratios,
                "random_seed": self.random_seed,
            },
            "samples": [s.to_dict() for s in self._all_samples],
        }
        filepath = Path(path)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info(f"Exported {self.total_samples} samples to {path}")

    # ─── Built-in Benchmark Dataset ──────────────────────────

    def _generate_builtin_samples(self) -> List[EmailSample]:
        """
        Generate a production-scale benchmark dataset via procedural generation.
        
        Target: 2000+ legitimate, 2000+ phishing, 500+ adversarial.
        Uses template expansion with randomized parameters to create
        statistically significant sample sizes across all categories
        and difficulty levels.
        """
        rng = random.Random(self.random_seed)
        samples: List[EmailSample] = []

        samples.extend(self._gen_legitimate(rng, count=2200))
        samples.extend(self._gen_known_phishing(rng, count=1400))
        samples.extend(self._gen_spear_phishing(rng, count=800))
        samples.extend(self._gen_adversarial(rng, count=600))

        logger.info(
            f"Generated {len(samples)} builtin samples: "
            f"legit={2200}, known_phish={1400}, spear={800}, adversarial={600}"
        )
        return samples

    # ═══════════════════════════════════════════════════════════
    # PROCEDURAL GENERATORS — Category A: Legitimate
    # ═══════════════════════════════════════════════════════════

    _LEGIT_DOMAINS = [
        "company.com", "megacorp.io", "globalbank.com", "techstartup.dev",
        "university.edu", "hospital.org", "lawfirm.com", "retailco.com",
        "energyco.com", "consulting-group.com", "media-inc.com",
        "finservices.com", "logistics-corp.com", "pharma-intl.com",
    ]

    _LEGIT_PLATFORMS = [
        ("noreply@github.com", "GitHub", "https://github.com"),
        ("noreply@zoom.us", "Zoom", "https://zoom.us"),
        ("notifications@slack.com", "Slack", "https://app.slack.com"),
        ("donotreply@jira.atlassian.net", "Jira", "https://phishnet.atlassian.net"),
        ("newsletter@linkedin.com", "LinkedIn", "https://www.linkedin.com"),
        ("noreply@teams.microsoft.com", "Microsoft Teams", "https://teams.microsoft.com"),
        ("alerts@pagerduty.com", "PagerDuty", "https://pagerduty.com"),
        ("notifications@trello.com", "Trello", "https://trello.com"),
        ("billing@aws.amazon.com", "Amazon Web Services", "https://console.aws.amazon.com"),
        ("order-confirm@amazon.com", "Amazon.com", "https://www.amazon.com"),
        ("noreply@google.com", "Google Workspace", "https://workspace.google.com"),
        ("no-reply@accounts.google.com", "Google", "https://myaccount.google.com"),
        ("noreply@figma.com", "Figma", "https://www.figma.com"),
        ("noreply@notion.so", "Notion", "https://www.notion.so"),
        ("noreply@vercel.com", "Vercel", "https://vercel.com"),
        ("support@stripe.com", "Stripe", "https://dashboard.stripe.com"),
    ]

    _FIRST_NAMES = [
        "John", "Sarah", "Michael", "Emily", "David", "Jessica", "Robert",
        "Alice", "James", "Linda", "Daniel", "Karen", "Christopher", "Lisa",
        "Matthew", "Patricia", "Andrew", "Susan", "Thomas", "Margaret",
        "William", "Jennifer", "Richard", "Elizabeth", "Joseph", "Nancy",
        "Charles", "Sandra", "Kevin", "Ashley", "Brian", "Dorothy",
        "Mark", "Stephanie", "Paul", "Rachel", "Steven", "Megan",
        "Ryan", "Samantha", "Timothy", "Olivia", "Jason", "Natalie",
    ]

    _LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Davis", "Miller",
        "Wilson", "Moore", "Taylor", "Anderson", "Thomas", "Jackson", "White",
        "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson",
        "Clark", "Rodriguez", "Lewis", "Lee", "Walker", "Hall", "Allen",
        "Young", "King", "Wright", "Lopez", "Hill", "Scott", "Green",
        "Adams", "Baker", "Gonzalez", "Nelson", "Carter", "Mitchell",
    ]

    _INTERNAL_SUBJECTS = [
        "Q{q} Budget Review Meeting",
        "Team Standup Notes - {date}",
        "Project {proj} Status Update",
        "Lunch order for {day}",
        "Office supplies request",
        "PTO Request: {date} - {date2}",
        "Re: Database migration plan",
        "Parking lot update",
        "New hire onboarding: {name}",
        "Monthly all-hands agenda",
        "{dept} department sync",
        "Updated org chart",
        "Re: Client meeting prep",
        "FYI: Server maintenance {day}",
        "Congratulations {name}!",
        "Happy birthday {name}!",
        "Re: Code review for PR #{num}",
        "Sprint {num} retrospective notes",
        "Release v{ver} deployed",
        "Vendor evaluation: {proj}",
    ]

    _INTERNAL_BODIES = [
        "Hi team, let's schedule the {subj} for next {day} at {time}. Please bring your reports. Best, {sender}",
        "Hi everyone, quick update on project {proj}: we're on track for the {day} deadline. Let me know if you have blockers.",
        "Dear {name}, please review the attached document and provide feedback by {day}. Thanks, {sender}",
        "FYI — the {dept} team completed the migration successfully. No action needed on your end.",
        "Reminder: The office will be closed on {date} for the holiday. Enjoy the break!",
        "Hey {name}, can we sync for 15 minutes this afternoon about the {proj} timeline?",
        "Please see the attached meeting notes from today's standup. Action items are highlighted.",
        "Just wanted to share that {name} received the Employee of the Month award. Congrats!",
        "The new {dept} policy has been finalized. Please review the attached PDF at your convenience.",
        "Hi all, maintenance is scheduled for {day} {time}. Expect brief downtime for the internal portal.",
    ]

    _SAFE_ATTACHMENTS = [
        {"filename": "Meeting_Notes.pdf", "content_type": "application/pdf"},
        {"filename": "Q4_Report.xlsx", "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {"filename": "Presentation.pptx", "content_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {"filename": "Policy_Update.pdf", "content_type": "application/pdf"},
        {"filename": "headshot.jpg", "content_type": "image/jpeg"},
        {"filename": "org_chart.png", "content_type": "image/png"},
        {"filename": "onboarding_checklist.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ]

    def _gen_legitimate(self, rng: random.Random, count: int) -> List[EmailSample]:
        """Generate legitimate email samples across difficulty levels."""
        samples: List[EmailSample] = []
        difficulties = ["easy"] * 50 + ["medium"] * 35 + ["hard"] * 15  # weighted

        for i in range(count):
            diff = rng.choice(difficulties)
            variant = rng.random()

            if variant < 0.55:
                # Internal company email
                s = self._gen_internal_legit(rng, i, diff)
            elif variant < 0.85:
                # Platform notification
                s = self._gen_platform_legit(rng, i, diff)
            else:
                # Transactional / newsletter
                s = self._gen_transactional_legit(rng, i, diff)

            samples.append(s)
        return samples

    def _gen_internal_legit(self, rng: random.Random, idx: int, difficulty: str) -> EmailSample:
        first = rng.choice(self._FIRST_NAMES)
        last = rng.choice(self._LAST_NAMES)
        domain = rng.choice(self._LEGIT_DOMAINS)
        sender = f"{first.lower()}.{last.lower()}@{domain}"
        display = f"{first} {last}"
        dept = rng.choice(["Engineering", "Marketing", "HR", "Finance", "Legal", "Sales", "Product", "Operations"])
        proj = rng.choice(["Phoenix", "Atlas", "Titan", "Nova", "Apex", "Orion", "Zenith", "Vanguard"])
        day = rng.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"])
        q = rng.randint(1, 4)
        num = rng.randint(100, 999)
        date_str = f"Jan {rng.randint(1,28)}"
        date2_str = f"Jan {rng.randint(15,28)}"
        ver = f"{rng.randint(1,5)}.{rng.randint(0,9)}.{rng.randint(0,9)}"
        time_str = f"{rng.randint(9,17)}:{rng.choice(['00','30'])}"
        name2 = f"{rng.choice(self._FIRST_NAMES)} {rng.choice(self._LAST_NAMES)}"

        subj_tmpl = rng.choice(self._INTERNAL_SUBJECTS)
        subj = subj_tmpl.format(q=q, date=date_str, date2=date2_str, proj=proj, day=day,
                                name=name2, dept=dept, num=num, ver=ver)
        body_tmpl = rng.choice(self._INTERNAL_BODIES)
        body = body_tmpl.format(subj=subj, day=day, time=time_str, proj=proj, sender=first,
                                name=name2, dept=dept, date=date_str)

        attachments = [rng.choice(self._SAFE_ATTACHMENTS)] if rng.random() < 0.25 else []
        links = [f"https://intranet.{domain}/wiki/{proj.lower()}"] if rng.random() < 0.15 else []

        auth = "spf=pass; dkim=pass; dmarc=pass"
        if difficulty == "medium" and rng.random() < 0.2:
            auth = "spf=pass; dkim=pass; dmarc=none"  # partial auth is still legit
        if difficulty == "hard" and rng.random() < 0.3:
            auth = "spf=pass; dkim=none; dmarc=none"  # forwarded mail

        return EmailSample(
            id=f"legit_{idx+1:05d}",
            sender=sender,
            sender_display_name=display,
            subject=subj,
            body=body,
            links=links,
            attachments=attachments,
            headers={"Authentication-Results": auth, "Received-SPF": "pass"},
            ground_truth="SAFE",
            category="CLEAN_LEGITIMATE",
            difficulty=difficulty,
        )

    def _gen_platform_legit(self, rng: random.Random, idx: int, difficulty: str) -> EmailSample:
        plat = rng.choice(self._LEGIT_PLATFORMS)
        sender, display, base_url = plat

        notif_types = [
            ("Pull request #{num} merged", "PR #{num} was merged into main. {changes} files changed."),
            ("Meeting in 15 minutes", "Reminder: '{meeting}' starts in 15 minutes."),
            ("New comment on your post", "{name} commented on your post: '{comment}'"),
            ("Weekly digest", "Here are your top updates this week from {display}."),
            ("{name} mentioned you", "{name} mentioned you in #{channel}: '{comment}'"),
            ("Build #{num} passed", "All checks passed for commit {hash}. Ready to deploy."),
            ("Invoice #{num}", "Your monthly invoice for ${amount} is ready. View details in your dashboard."),
            ("New sign-in detected", "A new sign-in was detected from {device} in {location}. If this was you, no action needed."),
        ]
        tmpl_subj, tmpl_body = rng.choice(notif_types)
        num = rng.randint(100, 9999)
        name2 = f"{rng.choice(self._FIRST_NAMES)}"
        subj = tmpl_subj.format(num=num, name=name2, meeting="Weekly Standup")
        body = tmpl_body.format(
            num=num, changes=rng.randint(1, 50), name=name2, display=display,
            channel="general", comment="Looks good to me!", hash=f"a{rng.randint(100000,999999):x}",
            amount=f"{rng.randint(10, 500):.2f}", device="Windows PC", location="New York, USA",
            meeting="Weekly Standup",
        )

        link = f"{base_url}/notifications/{rng.randint(10000,99999)}"
        return EmailSample(
            id=f"legit_{idx+1:05d}",
            sender=sender,
            sender_display_name=display,
            subject=subj,
            body=body,
            links=[link],
            body_html=f'<a href="{link}">View</a>',
            headers={"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass", "Received-SPF": "pass"},
            ground_truth="SAFE",
            category="CLEAN_LEGITIMATE",
            difficulty=difficulty,
        )

    def _gen_transactional_legit(self, rng: random.Random, idx: int, difficulty: str) -> EmailSample:
        tx_types = [
            {"sender": "noreply@shipping.fedex.com", "display": "FedEx", "subj": "Your package is on its way",
             "body": "Tracking #: {num}. Estimated delivery: {day}.", "link": "https://www.fedex.com/tracking"},
            {"sender": "receipts@uber.com", "display": "Uber", "subj": "Your trip receipt",
             "body": "Trip on {day}: ${amt}. {dist} miles. Thank you for riding with Uber.",
             "link": "https://riders.uber.com/trips"},
            {"sender": "noreply@netflix.com", "display": "Netflix", "subj": "Your Netflix payment receipt",
             "body": "Payment of ${amt} received for your Premium plan. Next billing date: {day}.",
             "link": "https://www.netflix.com/YourAccount"},
            {"sender": "no-reply@spotify.com", "display": "Spotify", "subj": "Your Wrapped {yr} is ready",
             "body": "You listened to {num} songs this year! Check out your personalized Wrapped.",
             "link": "https://open.spotify.com/wrapped"},
            {"sender": "billing@digitalocean.com", "display": "DigitalOcean",
             "subj": "Invoice #{num} for your account",
             "body": "Your invoice for ${amt} has been processed successfully.",
             "link": "https://cloud.digitalocean.com/account/billing"},
        ]
        tx = rng.choice(tx_types)
        num = rng.randint(10000, 99999)
        day = rng.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"])
        amt = f"{rng.uniform(5, 500):.2f}"

        return EmailSample(
            id=f"legit_{idx+1:05d}",
            sender=tx["sender"],
            sender_display_name=tx["display"],
            subject=tx["subj"].format(num=num, yr=2026),
            body=tx["body"].format(num=num, day=day, amt=amt, dist=rng.randint(1, 50), yr=2026),
            links=[tx["link"]],
            body_html=f'<a href="{tx["link"]}">View Details</a>',
            headers={"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass", "Received-SPF": "pass"},
            ground_truth="SAFE",
            category="CLEAN_LEGITIMATE",
            difficulty=difficulty,
        )

    # ═══════════════════════════════════════════════════════════
    # PROCEDURAL GENERATORS — Category B: Known Phishing
    # ═══════════════════════════════════════════════════════════

    _PHISH_BRANDS = [
        {"name": "PayPal", "domain": "paypal.com", "display": "PayPal Security"},
        {"name": "Microsoft", "domain": "microsoft.com", "display": "Microsoft Account Team"},
        {"name": "Apple", "domain": "apple.com", "display": "Apple Support"},
        {"name": "Amazon", "domain": "amazon.com", "display": "Amazon.com"},
        {"name": "Bank of America", "domain": "bankofamerica.com", "display": "Bank of America"},
        {"name": "Netflix", "domain": "netflix.com", "display": "Netflix Support"},
        {"name": "Google", "domain": "google.com", "display": "Google Security"},
        {"name": "Dropbox", "domain": "dropbox.com", "display": "Dropbox"},
        {"name": "LinkedIn", "domain": "linkedin.com", "display": "LinkedIn"},
        {"name": "Chase", "domain": "chase.com", "display": "Chase Bank"},
        {"name": "Wells Fargo", "domain": "wellsfargo.com", "display": "Wells Fargo"},
        {"name": "DHL", "domain": "dhl.com", "display": "DHL Express"},
        {"name": "USPS", "domain": "usps.com", "display": "USPS"},
        {"name": "Coinbase", "domain": "coinbase.com", "display": "Coinbase"},
    ]

    _PHISH_SUBJECT_TEMPLATES = [
        "URGENT: Your {brand} account has been limited",
        "Action Required: Verify your {brand} account",
        "Suspicious activity detected on your {brand} account",
        "{brand} Account Suspension Notice",
        "Your {brand} password expires today",
        "Unauthorized login attempt on your {brand} account",
        "Your {brand} account will be deactivated",
        "{brand}: Payment failed - update required",
        "Security alert: {brand} account compromised",
        "Your {brand} order #{num} has a problem",
        "Important: {brand} Terms of Service update",
        "Re: [URGENT] {brand} account recovery",
        "{brand} billing issue - immediate action required",
    ]

    _PHISH_BODY_TEMPLATES = [
        "We noticed unusual activity on your {brand} account. Your access has been limited until you verify your identity. Click the link below immediately to restore access or your account will be permanently suspended within {hours} hours.",
        "Your {brand} account will be deactivated in {hours} hours unless you verify your credentials. Click here to keep your account active. Failure to respond will result in data loss.",
        "We detected a suspicious transaction of ${amount} on your account. If you did not authorize this transaction, click the link below to dispute it immediately. Your account may be frozen.",
        "Dear customer, your {brand} password will expire today. To avoid losing access, update your password now using the secure link below. This is a mandatory security requirement.",
        "An unauthorized login was detected from {location}. If this was not you, secure your account immediately by clicking below. IP: {ip}",
        "Your {brand} account has been flagged for suspicious activity. We have temporarily limited your ability to send and receive funds. To restore full functionality, complete verification within {hours} hours.",
        "NOTICE: Due to a security breach, all {brand} users must reset their passwords. Use the link below to verify your account and set a new password. Accounts not verified within {hours} hours will be locked.",
    ]

    _SUSPICIOUS_TLDS = [".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                        ".club", ".work", ".click", ".link", ".info", ".biz", ".online"]

    _DANGEROUS_EXTS = [".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js",
                       ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".dll", ".hta"]

    def _gen_known_phishing(self, rng: random.Random, count: int) -> List[EmailSample]:
        """Generate known phishing email samples."""
        samples: List[EmailSample] = []
        for i in range(count):
            brand = rng.choice(self._PHISH_BRANDS)
            diff = rng.choice(["easy"] * 60 + ["medium"] * 30 + ["hard"] * 10)

            # Generate spoofed domain
            domain_style = rng.choice(["typo", "subdomain", "tld", "dash"])
            name_part = brand["domain"].split(".")[0]
            if domain_style == "typo":
                # Letter substitution: l→1, o→0, a→4
                subs = {"l": "1", "o": "0", "a": "4", "e": "3", "i": "1", "s": "5"}
                chars = list(name_part)
                pos = rng.randint(0, max(0, len(chars) - 1))
                if chars[pos].lower() in subs:
                    chars[pos] = subs[chars[pos].lower()]
                spoofed = "".join(chars) + ".com"
            elif domain_style == "subdomain":
                spoofed = f"{name_part}.com.verify-{rng.randint(100,999)}{rng.choice(self._SUSPICIOUS_TLDS)}"
            elif domain_style == "tld":
                spoofed = f"{name_part}{rng.choice(self._SUSPICIOUS_TLDS)}"
            else:
                spoofed = f"{name_part}-{'secure' if rng.random() < 0.5 else 'verify'}.com"

            sender = f"{rng.choice(['alert','security','support','admin','noreply','helpdesk'])}@{spoofed}"
            subj = rng.choice(self._PHISH_SUBJECT_TEMPLATES).format(
                brand=brand["name"], num=rng.randint(10000, 99999))
            body = rng.choice(self._PHISH_BODY_TEMPLATES).format(
                brand=brand["name"], hours=rng.choice([12, 24, 48]),
                amount=f"{rng.randint(100, 5000):.2f}",
                location=rng.choice(["Lagos, Nigeria", "Moscow, Russia", "Shanghai, China",
                                      "Unknown Location", "Bucharest, Romania"]),
                ip=f"{rng.randint(1,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,255)}",
            )

            # Auth results vary by difficulty
            if diff == "easy":
                auth = f"spf={rng.choice(['fail','softfail'])}; dkim={rng.choice(['fail','none'])}; dmarc=fail"
            elif diff == "medium":
                auth = f"spf={rng.choice(['pass','softfail'])}; dkim={rng.choice(['none','pass'])}; dmarc={rng.choice(['none','fail'])}"
            else:
                auth = "spf=pass; dkim=pass; dmarc=none"

            phish_link = f"http://{spoofed}/{rng.choice(['verify','login','secure','update','confirm'])}"
            attachments = []
            if rng.random() < 0.15:
                ext = rng.choice(self._DANGEROUS_EXTS)
                attachments = [{"filename": f"Document{ext}", "content_type": "application/octet-stream"}]

            samples.append(EmailSample(
                id=f"phish_{i+1:05d}",
                sender=sender,
                sender_display_name=brand["display"],
                subject=subj,
                body=body,
                links=[phish_link],
                body_html=f'<a href="{phish_link}">Click Here</a>',
                headers={"Authentication-Results": auth, "Received-SPF": auth.split(";")[0].split("=")[1].strip()},
                ground_truth="PHISHING",
                category="KNOWN_PHISHING",
                difficulty=diff,
                attachments=attachments,
                metadata={"spoofed_brand": brand["name"], "spoofed_domain": spoofed},
            ))
        return samples

    # ═══════════════════════════════════════════════════════════
    # PROCEDURAL GENERATORS — Category C: Spear Phishing
    # ═══════════════════════════════════════════════════════════

    _SPEAR_SCENARIOS = [
        {
            "role": "CFO", "theme": "wire_transfer",
            "subjects": [
                "Re: Q{q} Acquisition - Confidential Wire Transfer",
                "Urgent: Vendor payment required today",
                "Re: Board-approved disbursement",
            ],
            "bodies": [
                "Following up on our call about the acquisition. The board approved the wire transfer. Process ${amount} to the escrow account today. Details attached. Keep confidential. - {name}",
                "Hi, the vendor payment for ${amount} needs to go out today per the CEO's approval. Use the wire details in the attached PDF. Thanks, {name}",
            ],
        },
        {
            "role": "IT", "theme": "credential_harvest",
            "subjects": [
                "Mandatory Password Reset - Security Compliance",
                "IT: VPN certificate renewal required",
                "Action: Multi-factor authentication enrollment",
            ],
            "bodies": [
                "As part of our annual security audit, all employees must reset passwords by EOD. Use the secure portal below. Required by ISO 27001. - IT Security",
                "Your VPN certificate expires tomorrow. Renew it using the portal link below to maintain remote access. - IT Help Desk",
            ],
        },
        {
            "role": "Legal", "theme": "document_signing",
            "subjects": [
                "Confidential: Settlement Agreement for Review",
                "NDA - Signature Required by {day}",
                "Contract Amendment - Urgent Review Needed",
            ],
            "bodies": [
                "Attached is the settlement agreement. Opposing counsel agreed to terms. We need your signature by {day}. Return via the secure upload portal.",
                "The NDA for the {proj} deal needs your electronic signature. Please review and sign through the secure portal by end of day.",
            ],
        },
        {
            "role": "Recruiter", "theme": "job_offer",
            "subjects": [
                "Senior Engineer Position at FAANG - $350K+ TC",
                "Executive role opportunity - confidential",
                "Your application: Final round interview",
            ],
            "bodies": [
                "I found your profile and think you'd be perfect for a Staff Engineer role. TC is $350K-$500K. Complete the attached assessment and send it back. It takes 30 min.",
                "Congratulations! You've been selected for the final round. Please complete the technical evaluation attached and submit through our portal.",
            ],
        },
        {
            "role": "CEO", "theme": "urgent_request",
            "subjects": [
                "Quick favor", "Need your help urgently", "Are you available?",
                "Can you handle something?", "Time-sensitive request",
            ],
            "bodies": [
                "Hey, I'm in a board meeting and can't call. Can you purchase {n} gift cards at ${gc_amount} each? Send me the codes ASAP. I'll reimburse you. - {name}",
                "I need you to wire ${amount} to a vendor urgently. Regular process is too slow. Account details to follow. Keep this confidential. - {name}",
            ],
        },
        {
            "role": "Vendor", "theme": "invoice_fraud",
            "subjects": [
                "Updated banking details for Invoice #{num}",
                "IMPORTANT: Payment account change notification",
                "Re: Outstanding invoice - updated remittance info",
            ],
            "bodies": [
                "Please note our banking details have changed effective immediately. Use the new account information in the attached document for all future payments. - Accounts Receivable",
                "Due to a recent bank migration, please update our payment details. The new wire information is attached. All previous account numbers are now invalid.",
            ],
        },
    ]

    def _gen_spear_phishing(self, rng: random.Random, count: int) -> List[EmailSample]:
        """Generate sophisticated spear phishing samples."""
        samples: List[EmailSample] = []
        for i in range(count):
            scenario = rng.choice(self._SPEAR_SCENARIOS)
            name = f"{rng.choice(self._FIRST_NAMES)} {rng.choice(self._LAST_NAMES)}"
            domain = f"{rng.choice(['company','corp','firm','enterprise'])}-{rng.choice(['acq','consulting','services','group','legal'])}.com"
            sender = f"{rng.choice(['cfo','ceo','partner','admin','it-support','recruiter','accounts'])}@{domain}"
            q = rng.randint(1, 4)
            day = rng.choice(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"])
            proj = rng.choice(["Phoenix", "Atlas", "Titan", "Nova", "Zenith"])
            num = rng.randint(10000, 99999)

            subj = rng.choice(scenario["subjects"]).format(q=q, day=day, proj=proj, num=num)
            body = rng.choice(scenario["bodies"]).format(
                name=name, amount=f"{rng.randint(5,500) * 1000:,}",
                day=day, proj=proj, n=rng.randint(3, 10),
                gc_amount=rng.choice([100, 200, 500]),
                num=num,
            )

            # Spear phishing often passes authentication
            auth_style = rng.choice([
                "spf=pass; dkim=pass; dmarc=pass",
                "spf=pass; dkim=pass; dmarc=none",
                "spf=pass; dkim=none; dmarc=none",
            ])

            links, attachments = [], []
            if scenario["theme"] in ("credential_harvest", "document_signing"):
                tld = rng.choice(self._SUSPICIOUS_TLDS + [".com", ".io"])
                links = [f"https://{domain.replace('.com', '')}-portal{tld}/secure"]
            if scenario["theme"] in ("wire_transfer", "invoice_fraud", "document_signing"):
                ext = rng.choice([".pdf", ".docm", ".xlsm"])
                attachments = [{"filename": f"{rng.choice(['Wire_Instructions','Invoice','Contract','NDA'])}{ext}",
                                "content_type": "application/pdf" if ext == ".pdf" else "application/octet-stream"}]
            if scenario["theme"] == "job_offer":
                attachments = [{"filename": f"Assessment{rng.choice(['.js','.docm','.xlsm','.hta'])}",
                                "content_type": "application/octet-stream"}]

            samples.append(EmailSample(
                id=f"spear_{i+1:05d}",
                sender=sender,
                sender_display_name=f"{name} ({scenario['role']})",
                subject=subj,
                body=body,
                links=links,
                attachments=attachments,
                body_html=f'<a href="{links[0] if links else "#"}">Access Portal</a>' if links else "",
                headers={"Authentication-Results": auth_style, "Received-SPF": "pass"},
                ground_truth="PHISHING",
                category="SPEAR_PHISHING",
                difficulty=rng.choice(["hard"] * 70 + ["adversarial"] * 30),
                metadata={"attack_theme": scenario["theme"], "impersonated_role": scenario["role"]},
            ))
        return samples

    # ═══════════════════════════════════════════════════════════
    # PROCEDURAL GENERATORS — Category D: Adversarial Obfuscated
    # ═══════════════════════════════════════════════════════════

    _HOMOGLYPH_MAP = {
        "a": "а", "e": "е", "o": "о", "p": "р", "c": "с",
        "i": "і", "x": "х", "y": "у", "s": "ѕ",
    }

    def _gen_adversarial(self, rng: random.Random, count: int) -> List[EmailSample]:
        """Generate adversarial obfuscated phishing samples."""
        samples: List[EmailSample] = []
        techniques = [
            self._adv_homoglyph, self._adv_url_shortener, self._adv_base64_redirect,
            self._adv_double_extension, self._adv_bec_gift_card, self._adv_mixed,
        ]
        per_technique = count // len(techniques)
        remainder = count % len(techniques)

        for t_idx, technique in enumerate(techniques):
            n = per_technique + (1 if t_idx < remainder else 0)
            for j in range(n):
                idx = len(samples)
                samples.append(technique(rng, idx))
        return samples

    def _adv_homoglyph(self, rng: random.Random, idx: int) -> EmailSample:
        brand = rng.choice(self._PHISH_BRANDS)
        name = brand["domain"].split(".")[0]
        chars = list(name)
        for k in range(min(2, len(chars))):
            pos = rng.randint(0, len(chars) - 1)
            if chars[pos] in self._HOMOGLYPH_MAP:
                chars[pos] = self._HOMOGLYPH_MAP[chars[pos]]
        spoofed = "".join(chars) + "." + brand["domain"].split(".")[-1]
        return EmailSample(
            id=f"adv_{idx+1:05d}", sender=f"security@{spoofed}",
            sender_display_name=brand["display"],
            subject=f"Security Alert from {brand['name']}",
            body=f"We detected suspicious activity on your {brand['name']} account. Verify your identity immediately.",
            links=[f"https://{spoofed}/verify-identity"],
            headers={"Authentication-Results": "spf=none; dkim=none; dmarc=none", "Received-SPF": "none"},
            ground_truth="PHISHING", category="ADVERSARIAL_OBFUSCATED", difficulty="adversarial",
            metadata={"attack_type": "homoglyph", "target_brand": brand["name"]},
        )

    def _adv_url_shortener(self, rng: random.Random, idx: int) -> EmailSample:
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "shorturl.at"]
        brand = rng.choice(self._PHISH_BRANDS)
        short = f"https://{rng.choice(shorteners)}/{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=7))}"
        return EmailSample(
            id=f"adv_{idx+1:05d}", sender=f"alert@{brand['domain']}-notifications.com",
            sender_display_name=brand["display"],
            subject=f"Important: Action Required on Your {brand['name']} Account",
            body=f"Confirm recent changes to your {brand['name']} account via the link below.",
            links=[short],
            headers={"Authentication-Results": "spf=softfail; dkim=none; dmarc=none", "Received-SPF": "softfail"},
            ground_truth="PHISHING", category="ADVERSARIAL_OBFUSCATED", difficulty="adversarial",
            metadata={"attack_type": "url_shortener"},
        )

    def _adv_base64_redirect(self, rng: random.Random, idx: int) -> EmailSample:
        import base64
        target = rng.choice(["http://malware-payload.ru/drop", "http://credential-steal.tk/login", "http://phish-kit.xyz/cap"])
        encoded = base64.b64encode(target.encode()).decode()
        redir = f"https://redirect-{rng.randint(1000,9999)}.com/r?dest={encoded}"
        return EmailSample(
            id=f"adv_{idx+1:05d}", sender=f"noreply@redirect-{rng.randint(1000,9999)}.com",
            sender_display_name="Document Sharing",
            subject="Shared Document: Q4 Report",
            body="A document has been shared with you. This link expires in 24 hours.",
            links=[redir],
            headers={"Authentication-Results": "spf=pass; dkim=pass; dmarc=none", "Received-SPF": "pass"},
            ground_truth="PHISHING", category="ADVERSARIAL_OBFUSCATED", difficulty="adversarial",
            metadata={"attack_type": "base64_redirect"},
        )

    def _adv_double_extension(self, rng: random.Random, idx: int) -> EmailSample:
        benign = rng.choice([".pdf", ".docx", ".xlsx", ".png"])
        dangerous = rng.choice(self._DANGEROUS_EXTS)
        fname = f"Invoice_2026{benign}{dangerous}"
        return EmailSample(
            id=f"adv_{idx+1:05d}", sender=f"billing@invoice-{rng.randint(100,999)}.com",
            sender_display_name="Accounts Payable",
            subject=f"Invoice #{rng.randint(10000,99999)} - Payment Due",
            body="Please find your invoice attached. Payment due within 10 business days.",
            attachments=[{"filename": fname, "content_type": "application/octet-stream"}],
            headers={"Authentication-Results": "spf=pass; dkim=none; dmarc=none", "Received-SPF": "pass"},
            ground_truth="PHISHING", category="ADVERSARIAL_OBFUSCATED", difficulty="adversarial",
            metadata={"attack_type": "double_extension", "filename": fname},
        )

    def _adv_bec_gift_card(self, rng: random.Random, idx: int) -> EmailSample:
        ceo = f"{rng.choice(self._FIRST_NAMES)} {rng.choice(self._LAST_NAMES)}"
        first = ceo.split()[0]
        return EmailSample(
            id=f"adv_{idx+1:05d}", sender=f"{first.lower()}@company-exec.com",
            sender_display_name=ceo,
            subject=rng.choice(["Quick favor", "Need your help", "Urgent request", "Are you available?"]),
            body=f"Hey, purchase {rng.randint(3,10)} Amazon gift cards at ${rng.choice([100,200,500])} each. Send codes ASAP. In a meeting, can't call. - {first}",
            links=[], attachments=[],
            headers={"Authentication-Results": "spf=none; dkim=none; dmarc=none", "Received-SPF": "none"},
            ground_truth="PHISHING", category="ADVERSARIAL_OBFUSCATED", difficulty="adversarial",
            metadata={"attack_type": "bec_gift_card", "impersonated": ceo},
        )

    def _adv_mixed(self, rng: random.Random, idx: int) -> EmailSample:
        brand = rng.choice(self._PHISH_BRANDS)
        name = brand["domain"].split(".")[0]
        chars = list(name)
        for pos in range(len(chars)):
            if chars[pos] in self._HOMOGLYPH_MAP and rng.random() < 0.3:
                chars[pos] = self._HOMOGLYPH_MAP[chars[pos]]
        spoofed = "".join(chars) + "." + brand["domain"].split(".")[-1]
        shortener = rng.choice(["bit.ly", "tinyurl.com", "t.co"])
        short_id = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
        fname = f"Urgent_Notice{rng.choice(['.pdf','.docx'])}{rng.choice(['.exe','.js','.scr'])}"
        return EmailSample(
            id=f"adv_{idx+1:05d}", sender=f"urgent@{spoofed}",
            sender_display_name=brand["display"],
            subject=f"URGENT: {brand['name']} Security Breach",
            body=f"Unauthorized access detected on your {brand['name']} account. Click below and review the attached security report.",
            links=[f"https://{shortener}/{short_id}"],
            attachments=[{"filename": fname, "content_type": "application/octet-stream"}],
            headers={"Authentication-Results": "spf=none; dkim=none; dmarc=fail", "Received-SPF": "none"},
            ground_truth="PHISHING", category="ADVERSARIAL_OBFUSCATED", difficulty="adversarial",
            metadata={"attack_type": "mixed", "techniques": ["homoglyph", "url_shortener", "double_extension"]},
        )
