"""English/Georgian strings for the admin portal.

Deliberately a plain dict rather than gettext/Babel: the portal has a few
hundred strings, no plural-form complexity beyond one case handled inline,
and adding a compile step (.po -> .mo) to a Vercel build that already has to
stay dependency-light buys nothing here. Swap this for Babel the day a third
locale or a translator handoff arrives; until then this file is the whole
system and it is greppable.

Keys are dotted and grouped by the screen they appear on. `common.*` is for
strings that genuinely repeat across screens -- a key used twice is not
automatically common, since the same English word often needs different
Georgian depending on context.
"""

LANGUAGES = {"en": "EN", "ka": "KA"}
DEFAULT_LANGUAGE = "en"
LANGUAGE_COOKIE = "assetly_lang"

# Georgian is written by a native speaker's conventions for IT tooling:
# borrowed technical nouns stay in Latin script where that is what admins
# actually say ("API", "TOTP"), everything else is translated.
STRINGS: dict[str, dict[str, str]] = {
    # ── Chrome: sidebar, topbar, shared controls ──────────────────────
    "common.log_out": {"en": "Log out", "ka": "გასვლა"},
    "common.read_only": {"en": "Read-only", "ka": "მხოლოდ ნახვა"},
    "common.read_only_title": {
        "en": "Support role: read-only access",
        "ka": "მხარდაჭერის როლი: მხოლოდ ნახვის უფლება",
    },
    "common.save": {"en": "Save", "ka": "შენახვა"},
    "common.cancel": {"en": "Cancel", "ka": "გაუქმება"},
    "common.remove": {"en": "Remove", "ka": "წაშლა"},
    "common.revoke": {"en": "Revoke", "ka": "გაუქმება"},
    "common.required": {"en": "required", "ka": "სავალდებულო"},
    "common.optional": {"en": "optional", "ka": "არასავალდებულო"},
    "common.active": {"en": "Active", "ka": "აქტიური"},
    "common.revoked": {"en": "Revoked", "ka": "გაუქმებული"},
    "common.language": {"en": "Language", "ka": "ენა"},
    "common.none": {"en": "None", "ka": "არცერთი"},

    "nav.organization": {"en": "Organization", "ka": "ორგანიზაცია"},
    "nav.dashboard": {"en": "Dashboard", "ka": "მიმოხილვა"},
    "nav.computers": {"en": "Computers", "ka": "კომპიუტერები"},
    "nav.reports": {"en": "Reports", "ka": "ანგარიშები"},
    "nav.agents": {"en": "Agents", "ka": "აგენტები"},
    "nav.settings": {"en": "Settings", "ka": "პარამეტრები"},
    "nav.all_companies": {"en": "All companies", "ka": "ყველა კომპანია"},
    "nav.not_available_yet": {"en": "Not available yet", "ka": "ჯერ მიუწვდომელია"},
    "nav.recovery_codes": {"en": "Recovery codes", "ka": "აღდგენის კოდები"},
    "nav.audit_log": {"en": "Audit log", "ka": "აუდიტის ჟურნალი"},
    "nav.new_company": {"en": "+ New company", "ka": "+ ახალი კომპანია"},
    "nav.companies": {"en": "Companies", "ka": "კომპანიები"},

    # ── Sign in and two-factor ────────────────────────────────────────
    "login.title": {"en": "Sign in — Assetly", "ka": "შესვლა — Assetly"},
    "login.tagline": {
        "en": "IT Assets, always in view.",
        "ka": "IT აქტივები — ყოველთვის თვალსაწიერში.",
    },
    "login.email": {"en": "Email", "ka": "ელფოსტა"},
    "login.password": {"en": "Password", "ka": "პაროლი"},
    "login.submit": {"en": "Log in", "ka": "შესვლა"},

    "mfa.verify_title": {
        "en": "Two-factor authentication — Assetly",
        "ka": "ორფაქტორიანი ავთენტიფიკაცია — Assetly",
    },
    "mfa.verify_heading": {
        "en": "Two-factor authentication",
        "ka": "ორფაქტორიანი ავთენტიფიკაცია",
    },
    "mfa.code_label": {
        "en": "6-digit code from your authenticator, or a recovery code",
        "ka": "6-ნიშნა კოდი აპლიკაციიდან, ან აღდგენის კოდი",
    },
    "mfa.verify_submit": {"en": "Verify", "ka": "დადასტურება"},
    "mfa.setup_title": {
        "en": "Set up two-factor authentication — Assetly",
        "ka": "ორფაქტორიანი ავთენტიფიკაციის დაყენება — Assetly",
    },
    "mfa.setup_heading": {
        "en": "Set up two-factor authentication",
        "ka": "ორფაქტორიანი ავთენტიფიკაციის დაყენება",
    },
    "mfa.setup_intro": {
        "en": "Two-factor authentication is required for admin accounts. Scan the "
              "QR code below with 1Password, Google Authenticator, Microsoft "
              "Authenticator, or any TOTP app.",
        "ka": "ადმინისტრატორის ანგარიშისთვის ორფაქტორიანი ავთენტიფიკაცია "
              "სავალდებულოა. დაასკანერეთ ქვემოთ მოცემული QR კოდი 1Password-ით, "
              "Google Authenticator-ით, Microsoft Authenticator-ით ან ნებისმიერი "
              "TOTP აპლიკაციით.",
    },
    "mfa.manual_key": {
        "en": "Can't scan? Enter this key manually:",
        "ka": "ვერ ასკანერებთ? შეიყვანეთ ეს გასაღები ხელით:",
    },
    "mfa.six_digit_code": {"en": "6-digit code", "ka": "6-ნიშნა კოდი"},
    "mfa.setup_submit": {"en": "Verify and enable", "ka": "დადასტურება და ჩართვა"},

    "recovery.save_title": {
        "en": "Save your recovery codes — Assetly",
        "ka": "შეინახეთ აღდგენის კოდები — Assetly",
    },
    "recovery.save_heading": {
        "en": "Save your recovery codes",
        "ka": "შეინახეთ აღდგენის კოდები",
    },
    "recovery.warning": {
        "en": "These codes are shown once. Each one works once. They are the only "
              "way back into your account if you lose your authenticator.",
        "ka": "ეს კოდები მხოლოდ ერთხელ ჩანს და თითოეული მხოლოდ ერთხელ მუშაობს. "
              "ისინი ერთადერთი გზაა ანგარიშზე დასაბრუნებლად, თუ აპლიკაციას დაკარგავთ.",
    },
    "recovery.continue": {
        "en": "Continue to the console",
        "ka": "კონსოლზე გადასვლა",
    },
    "recovery.status_title": {"en": "Recovery codes — Assetly", "ka": "აღდგენის კოდები — Assetly"},
    "recovery.remaining_html": {
        "en": "You have <strong>{n}</strong> unused recovery code{s} remaining. "
              "Codes are shown only once, at the moment they are generated — this "
              "page never displays the codes themselves again.",
        "ka": "დარჩენილია <strong>{n}</strong> გამოუყენებელი აღდგენის კოდი. "
              "კოდები მხოლოდ ერთხელ, გენერაციის მომენტში ჩანს — ეს გვერდი მათ "
              "აღარასდროს აჩვენებს.",
    },
    "recovery.regenerate_warning": {
        "en": "Regenerating creates a brand new set of ten codes and immediately "
              "invalidates every code from the current set, including any you have "
              "printed or saved elsewhere.",
        "ka": "ხელახლა გენერაცია ქმნის ათი კოდის სრულიად ახალ ნაკრებს და მყისვე "
              "აუქმებს ამჟამინდელი ნაკრების ყველა კოდს — მათ შორის დაბეჭდილსა და "
              "სხვაგან შენახულს.",
    },
    "recovery.regenerate": {
        "en": "Regenerate recovery codes",
        "ka": "აღდგენის კოდების ხელახლა გენერაცია",
    },

    # ── Companies list ────────────────────────────────────────────────
    "companies.title": {"en": "Companies — Assetly", "ka": "კომპანიები — Assetly"},
    "companies.new_company": {"en": "New company", "ka": "ახალი კომპანია"},
    "companies.company_name": {"en": "Company name", "ka": "კომპანიის სახელი"},
    "companies.create": {"en": "Create company", "ka": "კომპანიის შექმნა"},
    "companies.name": {"en": "Name", "ka": "სახელი"},
    "companies.none_yet": {"en": "No companies yet.", "ka": "კომპანიები ჯერ არ არის."},
    "companies.legacy_conversion": {"en": "Legacy conversion", "ka": "ძველი გასაღების კონვერსია"},
    "companies.save_api_key": {
        "en": "Save this API key now — it will not be shown again:",
        "ka": "შეინახეთ ეს API გასაღები ახლავე — ხელახლა აღარ გამოჩნდება:",
    },

    # ── Dashboard ─────────────────────────────────────────────────────
    "dashboard.title": {"en": "Dashboard — Assetly", "ka": "მიმოხილვა — Assetly"},
    "dashboard.devices_across_company": {
        "en": "{n} device{s} across this company",
        "ka": "{n} მოწყობილობა ამ კომპანიაში",
    },
    "dashboard.total_devices": {"en": "Total Devices", "ka": "სულ მოწყობილობა"},
    "dashboard.across_this_company": {"en": "across this company", "ka": "ამ კომპანიაში"},
    "dashboard.online": {"en": "Online", "ka": "ხაზზე"},
    "dashboard.checked_in_within": {
        "en": "checked in within {label}",
        "ka": "შემოწმდა ბოლო {label}-ის განმავლობაში",
    },
    "dashboard.pending_sync": {"en": "Pending Sync", "ka": "სინქრონიზაციის მოლოდინში"},
    "dashboard.overdue": {"en": "overdue, needs action", "ka": "ვადაგადაცილებული, საჭიროებს რეაგირებას"},
    "dashboard.offline": {"en": "Offline", "ka": "გათიშული"},
    "dashboard.stale_or_never": {"en": "stale or never reported", "ka": "მოძველებული ან არასდროს მოხსენებული"},
    "dashboard.os_distribution": {"en": "OS Distribution", "ka": "ოპერაციული სისტემები"},
    "dashboard.os_in_fleet": {
        "en": "{n} operating system{s} in the fleet",
        "ka": "{n} ოპერაციული სისტემა პარკში",
    },

    # ── Computers list ────────────────────────────────────────────────
    "computers.title": {"en": "Computers — Assetly", "ka": "კომპიუტერები — Assetly"},
    "computers.devices_total": {"en": "{n} device{s} total", "ka": "სულ {n} მოწყობილობა"},
    "computers.search_placeholder": {
        "en": "Search hostname, serial, department…",
        "ka": "ძებნა: სახელი, სერიული ნომერი, დეპარტამენტი…",
    },
    "computers.all": {"en": "All", "ka": "ყველა"},
    "computers.online": {"en": "Online", "ka": "ხაზზე"},
    "computers.pending": {"en": "Pending", "ka": "მოლოდინში"},
    "computers.offline": {"en": "Offline", "ka": "გათიშული"},
    "computers.device": {"en": "Device", "ka": "მოწყობილობა"},
    "computers.department": {"en": "Department", "ka": "დეპარტამენტი"},
    "computers.os": {"en": "OS", "ka": "OS"},
    "computers.ram": {"en": "RAM", "ka": "ოპერატიული"},
    "computers.last_checkin": {"en": "Last check-in", "ka": "ბოლო შემოწმება"},
    "computers.status": {"en": "Status", "ka": "სტატუსი"},
    "computers.never": {"en": "never", "ka": "არასდროს"},

    # ── Device detail ─────────────────────────────────────────────────
    "device.title": {"en": "Device Detail — Assetly", "ka": "მოწყობილობის დეტალები — Assetly"},
    "device.detail": {"en": "Device Detail", "ka": "მოწყობილობის დეტალები"},
    "device.hardware_spec": {"en": "Hardware Specification", "ka": "აპარატურის მახასიათებლები"},
    "device.hostname": {"en": "Hostname", "ka": "ჰოსტის სახელი"},
    "device.serial_number": {"en": "Serial Number", "ka": "სერიული ნომერი"},
    "device.brand_model": {"en": "Brand / Model", "ka": "ბრენდი / მოდელი"},
    "device.operating_system": {"en": "Operating System", "ka": "ოპერაციული სისტემა"},
    "device.processor": {"en": "Processor", "ka": "პროცესორი"},
    "device.ram": {"en": "RAM", "ka": "ოპერატიული მეხსიერება"},
    "device.storage": {"en": "Storage", "ka": "მეხსიერება"},
    "device.owner": {"en": "Owner", "ka": "მფლობელი"},
    "device.department": {"en": "Department", "ka": "დეპარტამენტი"},
    "device.status": {"en": "Device Status", "ka": "მოწყობილობის სტატუსი"},
    "device.last_checkin": {"en": "Last check-in", "ka": "ბოლო შემოწმება"},
    "device.agent": {"en": "Agent", "ka": "აგენტი"},
    "device.credential": {"en": "Device Credential", "ka": "მოწყობილობის სერტიფიკატი"},
    "device.no_credential": {
        "en": "No enrollment credential on file for this device.",
        "ka": "ამ მოწყობილობისთვის რეგისტრაციის სერტიფიკატი არ არის.",
    },
    "device.this_machine_only": {"en": "this machine only", "ka": "მხოლოდ ეს მანქანა"},
    "device.checkin_history": {"en": "Check-in history", "ka": "შემოწმებების ისტორია"},
    "device.recent_checkins": {"en": "Recent Check-ins", "ka": "ბოლო შემოწმებები"},
    "device.received": {"en": "Received", "ka": "მიღებული"},
    "device.submitted_by": {"en": "Submitted by", "ka": "გამომგზავნი"},
    "device.no_checkins": {
        "en": "No check-ins recorded yet.",
        "ka": "შემოწმებები ჯერ არ დაფიქსირებულა.",
    },
    "device.revoke": {"en": "Revoke device", "ka": "მოწყობილობის გაუქმება"},
    "device.back": {"en": "Back", "ka": "უკან"},

    # ── Audit log ─────────────────────────────────────────────────────
    "audit.title": {"en": "Audit log — Assetly", "ka": "აუდიტის ჟურნალი — Assetly"},
    "audit.time": {"en": "Time", "ka": "დრო"},
    "audit.actor": {"en": "Actor", "ka": "შემსრულებელი"},
    "audit.action": {"en": "Action", "ka": "მოქმედება"},
    "audit.all_actions": {"en": "All actions", "ka": "ყველა მოქმედება"},
    "audit.all_companies": {"en": "All companies", "ka": "ყველა კომპანია"},
    "audit.target_company": {"en": "Target company", "ka": "სამიზნე კომპანია"},
    "audit.target_id": {"en": "Target id", "ka": "სამიზნის ID"},
    "audit.metadata": {"en": "Metadata", "ka": "მეტამონაცემები"},
    "audit.filter": {"en": "Filter", "ka": "ფილტრი"},
    "audit.no_entries": {
        "en": "No audit entries match this filter.",
        "ka": "ამ ფილტრს არცერთი ჩანაწერი არ ემთხვევა.",
    },

    # ── Settings page ─────────────────────────────────────────────────
    "settings.title": {"en": "Settings — Assetly", "ka": "პარამეტრები — Assetly"},
    "settings.subtitle": {
        "en": "Organization & account preferences",
        "ka": "ორგანიზაციისა და ანგარიშის პარამეტრები",
    },
    "settings.sec_rollout": {"en": "Rollout", "ka": "დანერგვა"},
    "settings.sec_rollout_sub": {
        "en": "Get the agent onto machines and manage the installers you have handed out.",
        "ka": "დააინსტალირეთ აგენტი კომპიუტერებზე და მართეთ გაცემული ინსტალატორები.",
    },
    "settings.sec_behaviour": {"en": "Check-in behaviour", "ka": "შემოწმების ქცევა"},
    "settings.sec_behaviour_sub": {
        "en": "How often employees are asked, what they are asked for, and how the prompt looks.",
        "ka": "რამდენად ხშირად ეკითხებით თანამშრომლებს, რას ეკითხებით და როგორ გამოიყურება შეტყობინება.",
    },
    "settings.sec_org": {"en": "Organization & access", "ka": "ორგანიზაცია და წვდომა"},
    "settings.sec_org_sub": {
        "en": "Account details, where alerts go, and the credentials this organization authenticates with.",
        "ka": "ანგარიშის დეტალები, შეტყობინებების მისამართი და ორგანიზაციის ავთენტიფიკაციის მონაცემები.",
    },

    "settings.company": {"en": "Company", "ka": "კომპანია"},
    "settings.api_key_prefix": {"en": "API key prefix", "ka": "API გასაღების პრეფიქსი"},
    "settings.status": {"en": "Status", "ka": "სტატუსი"},
    "settings.notification_email": {"en": "Notification email", "ka": "შეტყობინების ელფოსტა"},
    "settings.send_alerts_to": {"en": "Send alerts to", "ka": "შეტყობინებების მისამართი"},
    "settings.save_email": {"en": "Save email", "ka": "ელფოსტის შენახვა"},
    "settings.api_key": {"en": "API key", "ka": "API გასაღები"},
    "settings.rotate_explainer": {
        "en": "Rotating issues a new key and shows it once. Agents already installed keep "
              "working — they hold their own per-device credential.",
        "ka": "განახლება გასცემს ახალ გასაღებს და აჩვენებს მხოლოდ ერთხელ. უკვე "
              "დაინსტალირებული აგენტები განაგრძობენ მუშაობას — მათ საკუთარი, "
              "მოწყობილობაზე მიბმული სერტიფიკატი აქვთ.",
    },
    "settings.rotate": {"en": "Rotate API key", "ka": "API გასაღების განახლება"},
    "settings.api_key_read_only": {
        "en": "Read-only — full admin required to rotate or revoke.",
        "ka": "მხოლოდ ნახვა — განახლებასა და გაუქმებას სრული ადმინისტრატორი სჭირდება.",
    },

    "settings.schedule": {"en": "Check-in schedule", "ka": "შემოწმების განრიგი"},
    "settings.prompt_every": {"en": "Prompt employees every", "ka": "თანამშრომლებს ვკითხოთ ყოველ"},
    "settings.custom_interval": {"en": "Custom interval", "ka": "საკუთარი ინტერვალი"},
    "settings.cancel_retry": {
        "en": "If they cancel, ask again after",
        "ka": "თუ გააუქმებენ, ხელახლა ვკითხოთ",
    },
    "settings.save_schedule": {"en": "Save check-in schedule", "ka": "განრიგის შენახვა"},
    "settings.custom_option": {"en": "Custom…", "ka": "საკუთარი…"},

    "settings.fields": {"en": "Check-in fields", "ka": "შემოწმების ველები"},
    "settings.department_enabled": {"en": "Department field enabled", "ka": "დეპარტამენტის ველი ჩართულია"},
    "settings.department_required": {"en": "Department required", "ka": "დეპარტამენტი სავალდებულოა"},
    "settings.department_options": {
        "en": "Department options — one per line. Leave empty to restore the built-in list.",
        "ka": "დეპარტამენტების სია — თითო ხაზზე თითო. ცარიელი დატოვეთ ჩაშენებული სიის დასაბრუნებლად.",
    },
    "settings.save_fields": {"en": "Save check-in fields", "ka": "ველების შენახვა"},
    "settings.collected_every_checkin": {
        "en": "Collected at every check-in",
        "ka": "გროვდება ყოველი შემოწმებისას",
    },
    "settings.no_hardware_fields": {
        "en": "No hardware fields are collected.",
        "ka": "აპარატურის ველები არ გროვდება.",
    },
    "settings.dept_not_asked": {"en": "Not asked.", "ka": "არ იკითხება."},
    "settings.dept_required": {"en": "Asked, and required.", "ka": "იკითხება და სავალდებულოა."},
    "settings.dept_optional": {"en": "Asked, optional.", "ka": "იკითხება, არასავალდებულო."},
    "settings.read_only_hint": {
        "en": "Read-only — full admin required to change these.",
        "ka": "მხოლოდ ნახვა — შესაცვლელად სრული ადმინისტრატორია საჭირო.",
    },

    "settings.custom_fields": {"en": "Custom fields", "ka": "დამატებითი ველები"},
    "settings.field_label": {"en": "Field label", "ka": "ველის დასახელება"},
    "settings.new_field_label": {"en": "New custom field label", "ka": "ახალი ველის დასახელება"},
    "settings.add_custom_field": {"en": "Add custom field", "ka": "ველის დამატება"},
    "settings.remove_field_q": {"en": "Remove this field?", "ka": "წავშალოთ ეს ველი?"},
    "settings.yes_remove": {"en": "Yes, remove", "ka": "დიახ, წაშალე"},
    "settings.remove_named": {"en": "Remove {name}", "ka": "წაშალე {name}"},
    "settings.no_custom_fields": {
        "en": "No custom fields. Full admin required to add one.",
        "ka": "დამატებითი ველები არ არის. დასამატებლად სრული ადმინისტრატორია საჭირო.",
    },

    "settings.appearance": {"en": "Agent window appearance", "ka": "აგენტის ფანჯრის იერსახე"},
    "settings.appearance_reach": {
        "en": "Changes reach every installed agent on its next check-in — no new download needed.",
        "ka": "ცვლილებები ყველა დაინსტალირებულ აგენტს მომდევნო შემოწმებისას მიუვა — ხელახლა ჩამოტვირთვა საჭირო არ არის.",
    },
    "settings.appearance_customised": {
        "en": "{n} of {total} settings are customised.",
        "ka": "{total}-დან {n} პარამეტრია შეცვლილი.",
    },
    "settings.appearance_default": {
        "en": "Everything is currently at its built-in default.",
        "ka": "ამჟამად ყველაფერი ნაგულისხმევ მდგომარეობაშია.",
    },
    "settings.may_use": {"en": "may use", "ka": "შეიძლება გამოიყენოთ"},
    "settings.colours": {
        "en": "Colours — six hex digits, e.g. <code>#1866F2</code>. Combinations that would be "
              "unreadable on an employee’s screen are rejected when you save.",
        "ka": "ფერები — ექვსი თექვსმეტობითი სიმბოლო, მაგ. <code>#1866F2</code>. კომბინაციები, "
              "რომლებიც თანამშრომლის ეკრანზე წაუკითხავი იქნება, შენახვისას უარყოფილი იქნება.",
    },
    "settings.colour_aria": {
        "en": "{name} colour, six hex digits",
        "ka": "{name} — ფერი, ექვსი თექვსმეტობითი სიმბოლო",
    },
    "settings.save_appearance": {"en": "Save appearance", "ka": "იერსახის შენახვა"},
    "settings.clear_to_default": {
        "en": "Clear any box and save to put that one setting back to its built-in default.",
        "ka": "გაასუფთავეთ ველი და შეინახეთ, რომ ის პარამეტრი ნაგულისხმევს დაუბრუნდეს.",
    },

    "settings.download": {"en": "Download agent", "ka": "აგენტის ჩამოტვირთვა"},
    "settings.download_explainer": {
        "en": "Each download embeds a fresh enrollment token, configured for this company — "
              "nothing to edit after downloading. Downloading one platform does not affect "
              "installers you downloaded earlier, so macOS, Windows and Linux can be rolled "
              "out together and devices already reporting are unaffected. "
              "<strong>Expected devices</strong> caps how many machines that token may enroll "
              "(leave headroom for re-imaged machines); <strong>token valid for</strong> sets "
              "how long it stays usable. <strong>Windows MSI</strong> is for IT rather than "
              "one person: a zip holding the installer and a Deploy.cmd with the msiexec line "
              "for Intune, SCCM or GPO. It installs per machine, covers every user of a PC, "
              "and uninstalls from Add/Remove Programs.",
        "ka": "თითოეული ჩამოტვირთვა შეიცავს ახალ სარეგისტრაციო ტოკენს, უკვე კონფიგურირებულს "
              "ამ კომპანიისთვის — ჩამოტვირთვის შემდეგ არაფრის რედაქტირება არ სჭირდება. "
              "ერთი პლატფორმის ჩამოტვირთვა არ მოქმედებს ადრე ჩამოტვირთულ ინსტალატორებზე, "
              "ამიტომ macOS, Windows და Linux ერთად შეიძლება დაინერგოს, უკვე მომუშავე "
              "მოწყობილობებზე ზეგავლენის გარეშე. <strong>მოსალოდნელი მოწყობილობები</strong> "
              "განსაზღვრავს, რამდენ მანქანას შეუძლია ამ ტოკენით რეგისტრაცია (დატოვეთ მარაგი "
              "ხელახლა დაყენებული მანქანებისთვის); <strong>ტოკენის ვადა</strong> კი — რამდენ "
              "ხანს დარჩება გამოსადეგი. <strong>Windows MSI</strong> განკუთვნილია IT-სთვის და "
              "არა ერთი მომხმარებლისთვის: zip არქივი, რომელიც შეიცავს ინსტალატორს და "
              "Deploy.cmd-ს msiexec ბრძანებით Intune-ის, SCCM-ის ან GPO-სთვის. ის ეყენება "
              "მთელ მანქანაზე, მოიცავს კომპიუტერის ყველა მომხმარებელს და იშლება "
              "Add/Remove Programs-იდან.",
    },
    "settings.expected_devices": {"en": "Expected devices", "ka": "მოსალოდნელი მოწყობილობები"},
    "settings.token_valid_for": {"en": "Token valid for", "ka": "ტოკენის ვადა"},
    "settings.download_btn": {"en": "Download", "ka": "ჩამოტვირთვა"},
    "settings.download_for": {"en": "Download for {platform}", "ka": "ჩამოტვირთვა {platform}-ისთვის"},
    "settings.download_revoked": {
        "en": "Company is revoked — downloads are disabled.",
        "ka": "კომპანია გაუქმებულია — ჩამოტვირთვა გათიშულია.",
    },
    "settings.download_read_only": {
        "en": "Read-only — full admin required to download installers.",
        "ka": "მხოლოდ ნახვა — ინსტალატორის ჩამოსატვირთად სრული ადმინისტრატორია საჭირო.",
    },
    "settings.days": {"en": "{n} days", "ka": "{n} დღე"},

    "settings.legacy": {"en": "Legacy key conversion", "ka": "ძველი გასაღების კონვერსია"},
    "settings.legacy_none": {"en": "No devices yet.", "ka": "მოწყობილობები ჯერ არ არის."},
    "settings.legacy_converted": {
        "en": "{converted} / {total} devices have converted to a per-device credential.",
        "ka": "{total}-დან {converted} მოწყობილობა გადავიდა ინდივიდუალურ სერტიფიკატზე.",
    },
    "settings.legacy_last": {
        "en": "Most recent legacy check-in: {when}.",
        "ka": "ბოლო ძველი ტიპის შემოწმება: {when}.",
    },

    "settings.tokens": {"en": "Enrollment tokens", "ka": "სარეგისტრაციო ტოკენები"},
    "settings.tokens_explainer": {
        "en": "Revoking a token blocks future enrollments from that installer only — it does not "
              "touch devices that already enrolled with it, and they keep checking in normally. "
              "A device count in amber means the token is near its cap; once it is reached, new "
              "machines cannot enroll with that installer and you will need to download a new one.",
        "ka": "ტოკენის გაუქმება ბლოკავს მხოლოდ ამ ინსტალატორით მომავალ რეგისტრაციებს — უკვე "
              "რეგისტრირებულ მოწყობილობებს არ ეხება და ისინი ჩვეულებრივ განაგრძობენ შემოწმებას. "
              "ყვითლად მონიშნული რიცხვი ნიშნავს, რომ ტოკენი ლიმიტს უახლოვდება; ლიმიტის "
              "ამოწურვის შემდეგ ახალი მანქანები ვეღარ დარეგისტრირდებიან და ახალი ინსტალატორის "
              "ჩამოტვირთვა დაგჭირდებათ.",
    },
    "settings.tok_label": {"en": "Label", "ka": "დასახელება"},
    "settings.tok_token": {"en": "Token", "ka": "ტოკენი"},
    "settings.tok_expires": {"en": "Expires", "ka": "ვადა"},
    "settings.tok_devices": {"en": "Devices", "ka": "მოწყობილობები"},
    "settings.tok_unlimited": {"en": "unlimited", "ka": "შეუზღუდავი"},
    "settings.tokens_none": {
        "en": "No enrollment tokens yet. Download an installer above to create one.",
        "ka": "სარეგისტრაციო ტოკენები ჯერ არ არის. შესაქმნელად ჩამოტვირთეთ ინსტალატორი ზემოთ.",
    },

    "settings.danger": {"en": "Danger zone", "ka": "საშიში ზონა"},
    "settings.danger_explainer": {
        "en": "Revoking stops every agent in this organization from checking in and disables "
              "installer downloads. Devices stay in the records; reporting stops. This cannot "
              "be undone from the portal.",
        "ka": "გაუქმება შეაჩერებს ამ ორგანიზაციის ყველა აგენტის შემოწმებას და გათიშავს "
              "ინსტალატორების ჩამოტვირთვას. მოწყობილობები ჩანაწერებში დარჩება, მაგრამ "
              "მოხსენება შეწყდება. პორტალიდან ამის დაბრუნება შეუძლებელია.",
    },
    "settings.revoke_named": {"en": "Revoke {name}", "ka": "გააუქმე {name}"},

    # Save confirmations, shown after a redirect.
    "saved.email": {"en": "Notification email updated.", "ka": "შეტყობინების ელფოსტა განახლდა."},
    "saved.schedule": {"en": "Check-in schedule saved.", "ka": "შემოწმების განრიგი შენახულია."},
    "saved.fields": {"en": "Check-in fields saved.", "ka": "შემოწმების ველები შენახულია."},
    "saved.custom-field-added": {"en": "Custom field added.", "ka": "დამატებითი ველი დაემატა."},
    "saved.custom-field-removed": {"en": "Custom field removed.", "ka": "დამატებითი ველი წაიშალა."},
    "saved.appearance": {"en": "Agent window appearance saved.", "ka": "აგენტის ფანჯრის იერსახე შენახულია."},
    # Duration units. English pluralises with {s}; Georgian nouns after a
    # numeral stay in the singular, so the KA strings simply omit it.
    # Enrollment-token lifecycle, as stored in the database. Keyed by the raw
    # status value so the template can look one up directly.
    "token_status.active": {"en": "Active", "ka": "აქტიური"},
    "token_status.revoked": {"en": "Revoked", "ka": "გაუქმებული"},
    "token_status.expired": {"en": "Expired", "ka": "ვადაგასული"},
    "unit.hour": {"en": "{n} hour{s}", "ka": "{n} საათი"},
    "unit.day": {"en": "{n} day{s}", "ka": "{n} დღე"},
    "unit.week": {"en": "{n} week{s}", "ka": "{n} კვირა"},
    "unit.month": {"en": "{n} month{s}", "ka": "{n} თვე"},
    "unit.year": {"en": "{n} year{s}", "ka": "{n} წელი"},
    "unit.second": {"en": "{n} second{s}", "ka": "{n} წამი"},
    "unit.hours": {"en": "hours", "ka": "საათი"},
    "unit.days": {"en": "days", "ka": "დღე"},
    "unit.weeks": {"en": "weeks", "ka": "კვირა"},
    "unit.months": {"en": "months", "ka": "თვე"},
    "unit.years": {"en": "years", "ka": "წელი"},
    "settings.schedule_summary": {
        "en": "Employees are prompted every {interval}; if they cancel, they are "
              "asked again after {retry}.",
        "ka": "თანამშრომლებს შეტყობინება ეგზავნებათ ყოველ {interval}-ში; თუ "
              "გააუქმებენ, ხელახლა ეკითხებიან {retry}-ის შემდეგ.",
    },
    "saved.token-revoked": {
        "en": "Enrollment token revoked. Devices already enrolled are unaffected.",
        "ka": "სარეგისტრაციო ტოკენი გაუქმდა. უკვე რეგისტრირებულ მოწყობილობებზე ეს არ მოქმედებს.",
    },
}


def resolve_language(request) -> str:
    """Cookie first, then the browser's Accept-Language, then English.

    The cookie is the only thing the user controls directly, so it wins over
    a browser preference they may not even know they have set. Anything
    unrecognised falls back rather than raising: a hand-edited cookie must
    not be able to 500 the portal.
    """
    cookie = request.cookies.get(LANGUAGE_COOKIE)
    if cookie in LANGUAGES:
        return cookie
    header = request.headers.get("accept-language", "")
    for chunk in header.split(","):
        tag = chunk.split(";")[0].strip().lower()
        # "ka-GE" and "ka" both mean Georgian.
        primary = tag.split("-")[0]
        if primary in LANGUAGES:
            return primary
    return DEFAULT_LANGUAGE


def translate(lang: str, key: str, **kwargs) -> str:
    """Look up `key` in `lang`, falling back to English then to the key.

    Returning the key itself for an unknown lookup is deliberate: a missing
    string shows up as `settings.save_schedule` on the page, which is ugly
    and therefore gets reported, instead of rendering as an empty element
    that nobody notices.
    """
    entry = STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(lang) or entry.get(DEFAULT_LANGUAGE) or key
    if kwargs:
        try:
            return text.format(**kwargs)
        except (KeyError, IndexError):
            # A translation with a stray brace must not take the page down.
            return text
    return text


def translator(lang: str):
    """The `t` callable handed to templates."""
    def t(key: str, **kwargs) -> str:
        return translate(lang, key, **kwargs)
    return t


def i18n_context(request) -> dict:
    """Jinja context processor: every template gets `t`, `lang`, and the
    list of languages for the switcher, without any handler having to pass
    them explicitly."""
    lang = resolve_language(request)
    return {"t": translator(lang), "lang": lang, "languages": LANGUAGES}