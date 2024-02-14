from faker import Faker
from stix2 import ThreatActor, Identity, Malware, Tool, Indicator, AttackPattern, Campaign, IntrusionSet, Vulnerability
from datetime import datetime, timedelta
import random
import uuid

fake = Faker()


def create_threat_actors(count):
    templates = [
        "{} Bear",
        "{} Panda",
        "{} Group",
        "{} Squad",
        "{} Collective",
        "{} APT",
        "{} Brigade",
        "{} Syndicate"
    ]
    threat_actor_types = ["crime-syndicate", "hacker", "insider", "nation-state", "terrorist"]
    roles = ["agent", "director", "independent", "infrastructure-architect", "sponsor"]
    sophistication_levels = ["none", "minimal", "intermediate", "advanced", "expert", "innovator"]
    resource_levels = ["individual", "club", "contest", "team", "organization", "government"]
    motivations = ["ideological", "economic", "espionage", "financial", "revenge", "notoriety"]

    fake_threat_actors = []
    for _ in range(count):
        name = random.choice(templates).format(fake.word().capitalize())
        description = "Generated fake Threat Actor."
        threat_actor_type = random.choice(threat_actor_types)
        alias = fake.word().capitalize()
        first_seen = fake.date_between(start_date="-10y", end_date="today")
        last_seen = fake.date_between(start_date=first_seen, end_date="today")
        role = random.choice(roles)
        goal = "Goal: " + fake.sentence()
        sophistication = random.choice(sophistication_levels)
        resource_level = random.choice(resource_levels)
        primary_motivation = random.choice(motivations)
        secondary_motivation = random.choice([m for m in motivations if m != primary_motivation])

        fake_threat_actor = ThreatActor(
            name=name,
            description=description,
            threat_actor_types=[threat_actor_type],
            aliases=[alias],
            first_seen=first_seen,
            last_seen=last_seen,
            roles=[role],
            goals=[goal],
            sophistication=sophistication,
            resource_level=resource_level,
            primary_motivation=primary_motivation,
            secondary_motivations=[secondary_motivation]
        )

        fake_threat_actors.append(fake_threat_actor)

    return fake_threat_actors


def create_identities(count):

    identity_classes = ["individual", "group", "organization", "class", "unknown"]
    sectors = ["financial", "healthcare", "government", "information technology", "education"]
    roles = ["administrator", "user", "developer", "analyst", "researcher"]

    fake_identities = []
    for _ in range(count):
        now = datetime.now()
        name = fake.name()
        description = "Generated fake Identity."
        identity_class = random.choice(identity_classes)
        sector = random.choice(sectors)
        role = random.choice(roles)
        contact_info = f"contact@{fake.word().lower()}.com"

        fake_identity =Identity(
            name= name,
            description= description,
            roles= [role],
            identity_class= identity_class,
            sectors= [sector],
            contact_information= contact_info
        )

        fake_identities.append(fake_identity)

    return fake_identities

def create_malware(count):
    templates = [
        "{} Virus",
        "{} Worm",
        "{} Trojan",
        "{} Ransomware",
        "{} Botnet",
        "{} Spyware",
        "{} Rootkit",
        "{} FilelessMalware",
        "{} Adware",
        "{} Keylogger",
        "{} Cryptojacker",
        "{} Wiper"
    ]
    malware_types = [
        "backdoor", "bot", "ddos", "dropper", "exploit-kit",
        "keylogger", "ransomware", "remote-access-trojan", "resource-exploitation",
        "rogue-security-software", "rootkit", "screen-capture", "spyware",
        "trojan", "virus", "worm"
    ]
    kill_chain_phases = [
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "reconnaissance"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "delivery"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "exploitation"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "installation"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "command-and-control"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "actions-on-objectives"}
    ]
    capabilities = [
        "avoids-analysis", "avoids-detection", "captures-input", "cleans-traces",
        "commits-fraud", "communicates-with-c2", "compromises-data-integrity",
        "compromises-system", "controls-remote-systems", "escalates-privileges",
        "evades-av", "exfiltrates-data", "harvests-credentials", "hides-artifacts",
        "hides-executing-code", "infects-files", "persists-after-system-reboot",
        "prevents-artifact-access", "prevents-artifact-deletion",
        "probes-network-environment", "self-modifies", "steals-authentication-tokens",
        "violates-system-operational-integrity"
    ]

    fake_malwares = []
    for _ in range(count):
        name = random.choice(templates).format(fake.word().capitalize())
        description = "Generated fake Malware."
        malware_type = random.choice(malware_types)
        is_family = random.choice([True, False])
        aliases = [fake.word().capitalize() for _ in range(random.randint(1, 3))]
        first_seen = fake.date_between(start_date="-10y", end_date="today")
        last_seen = fake.date_between(start_date=first_seen, end_date="today")
        operating_system_refs = ["software--" + fake.uuid4() for _ in range(random.randint(1, 3))]
        architecture_execution_envs = ["x86", "x64"]
        implementation_languages = ["C", "C++", "Assembly"]
        capability = random.choice(capabilities)
        kill_chain_phase = random.choice(kill_chain_phases)

        fake_malware = Malware(
            name=name,
            description=description,
            malware_types=[malware_type],
            is_family=is_family,
            aliases=aliases,
            kill_chain_phases=[kill_chain_phase],
            first_seen=first_seen,
            last_seen=last_seen,
            operating_system_refs=operating_system_refs,
            architecture_execution_envs=architecture_execution_envs,
            implementation_languages=implementation_languages,
            capabilities=[capability]
        )

        fake_malwares.append(fake_malware)

    return fake_malwares


def create_indicators(count):
    templates = [
        "{} PhishingActivity",
        "{} MalwareSignature",
        "{} AnomalousTraffic",
        "{} SuspiciousLogin",
        "{} DataExfiltrationSignal"
    ]
    indicator_types = [
        "anomalous-activity", "malicious-activity", "attribution",
        "compromised", "benign"
    ]

    fake_indicators = []
    for _ in range(count):
        name = random.choice(templates).format(fake.word().capitalize())
        pattern = "[file:hashes.'SHA-256' = '{}']".format(fake.sha256())
        pattern_type = "stix"
        description = "Generated fake Indicator"
        indicator_type = random.choice(indicator_types)

        fake_indicator = Indicator(
            name=name,
            description=description,
            pattern=pattern,
            pattern_type=pattern_type,
            indicator_types=[indicator_type]
        )

        fake_indicators.append(fake_indicator)

    return fake_indicators


def create_attack_patterns(count):
    templates = [
        "{} Phishing",
        "{} SpearPhishing",
        "{} DriveByCompromise",
        "{} ExploitPublicFacingApplication"
    ]
    kill_chain_phases = [
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "reconnaissance"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "delivery"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "exploitation"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "installation"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "command-and-control"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "actions-on-objectives"}
    ]

    fake_attack_patterns = []
    for _ in range(count):
        now = datetime.now()
        name = random.choice(templates).format(fake.word().capitalize())
        description = "Generated fake Attack Pattern."
        external_references = [{
            "source_name": "capec",
            "external_id": f"CAPEC-{random.randint(1, 500)}",
            "url": f"https://capec.mitre.org/data/definitions/{random.randint(1, 500)}.html",
            "description": "Reference to a common attack pattern enumeration and classification."
        }]
        aliases = [f"{name} Variant {i}" for i in range(1, random.randint(2, 4))]
        kill_chain_phase = random.choice(kill_chain_phases)

        fake_attack_pattern =AttackPattern(
            spec_version="2.1",
            id= f"attack-pattern--{uuid.uuid4()}",
            created= now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            modified=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            name= name,
            description=description,
            aliases= aliases,
            kill_chain_phases= [kill_chain_phase],
            external_references= external_references
    )

        fake_attack_patterns.append(fake_attack_pattern)

    return fake_attack_patterns


def create_campaigns(count):
    templates = [
        "Operation {}",
        "{} Threat",
        "Project {}",
        "{} Offensive",
        "{} Maneuver",
        "{} Wave",
        "{} Blitz"
    ]
    objectives = [
        "Intelligence gathering",
        "Disruption of services",
        "Theft of intellectual property",
        "Reputation damage",
        "Strategic positioning"
    ]

    fake_campaigns = []
    for _ in range(count):
        now = datetime.now()
        name = random.choice(templates).format(fake.word().capitalize())
        description = "Generated fake Campaign"
        aliases = [f"{name} Variant {i}" for i in range(1, random.randint(2, 4))]
        first_seen = (now - timedelta(days=random.randint(10, 1000))).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_seen = (now - timedelta(days=random.randint(1, 9))).strftime("%Y-%m-%dT%H:%M:%SZ")
        objective = random.choice(objectives)

        fake_campaign =Campaign(
            name= name,
            description=description,
            aliases=aliases,
            first_seen= first_seen,
            last_seen=last_seen,
            objective= objective
        )

        fake_campaigns.append(fake_campaign)

    return fake_campaigns


def create_intrusion_sets(count):
    templates = [
        "{} Recon",
        "{} Domination",
        "{} Exploitation",
        "{} Disruption",
        "{} Theft"
    ]
    resource_levels = ["individual", "club", "team", "organization", "government"]
    motivations = ["ideological", "economic", "espionage", "financial", "revenge", "notoriety"]

    fake_intrusion_sets = []
    for _ in range(count):
        now = datetime.now()
        name = random.choice(templates).format(fake.word().capitalize())
        description = "Generated fake Intrusion Set"
        aliases = [f"{name} Variant {i}" for i in range(1, random.randint(2, 4))]
        first_seen = (now - timedelta(days=random.randint(10, 1000))).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_seen = (now - timedelta(days=random.randint(1, 9))).strftime("%Y-%m-%dT%H:%M:%SZ")
        goals = [f"Goal {i}: " + fake.sentence() for i in range(1, random.randint(2, 4))]
        resource_level = random.choice(resource_levels)
        primary_motivation = random.choice(motivations)
        secondary_motivations = random.sample([m for m in motivations if m != primary_motivation],
                                              k=random.randint(1, len(motivations) - 1))

        fake_intrusion_set = IntrusionSet(
            name= name,
            description= description,
            aliases= aliases,
            first_seen= first_seen,
            last_seen=last_seen,
            goals=goals,
            resource_level= resource_level,
            primary_motivation= primary_motivation,
            secondary_motivations=secondary_motivations
        )

        fake_intrusion_sets.append(fake_intrusion_set)

    return fake_intrusion_sets


def create_vulnerabilities(count):
    templates = [
        "{} Misconfiguration",
        "{} UnsecuredAPI",
        "{} OutdatedSoftware",
        "{} ZeroDay",
        "{} CredentialLeak",
        "{} AccessControlIssue",
        "{} SharedResponsibilityFlaw"
    ]
    cve_years = list(range(1999, datetime.now().year + 1))

    fake_vulnerabilities = []
    for _ in range(count):
        now = datetime.now()
        name = random.choice(templates).format(fake.word().capitalize())
        description = "Generated fake Vulnerability."
        cve_id = f"CVE-{random.choice(cve_years)}-{random.randint(1000, 9999)}"

        external_references = [{
            "source_name": "cve",
            "external_id": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "description": "National Vulnerability Database entry."
        }]

        fake_vulnerability = Vulnerability(
            name= name,
            description= description,
            external_references= external_references
        )

        fake_vulnerabilities.append(fake_vulnerability)

    return fake_vulnerabilities


def create_tools(count):
    templates = [
        "{} Scanner",
        "{} Firewall",
        "{} Encryptor",
        "{} Analyzer",
        "{} Protector"
    ]
    tool_types = ["network-capture", "password-cracking", "intrusion-detection", "forensic", "encryption"]
    kill_chain_phases = [
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "reconnaissance"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "weaponization"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "delivery"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "exploitation"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "installation"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "command-and-control"},
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "actions-on-objectives"}
    ]

    fake_tools = []
    for _ in range(count):
        now = datetime.now()
        tool_name = random.choice(templates).format(fake.word().capitalize())
        tool_description = "Generated fake Tool."
        tool_type = random.choice(tool_types)
        aliases = [f"{tool_name} Alias {i}" for i in range(1, random.randint(2, 3))]
        tool_version = f"{random.randint(1, 10)}.{random.randint(0, 9)}"

        fake_tool = Tool(
            name=tool_name,
            description= tool_description,
            tool_types= [tool_type],
            aliases=aliases,
            kill_chain_phases= kill_chain_phases,
            tool_version=tool_version
        )

        fake_tools.append(fake_tool)

    return fake_tools