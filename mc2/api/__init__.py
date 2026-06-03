from fastapi import APIRouter

from .routes_auth import router as auth_router
from .routes_mfa import router as mfa_router
from .routes_dashboard import router as dashboard_router
from .routes_defense import router as defense_router
from .routes_policy import router as policy_router
from .routes_license import router as license_router
from .routes_envelope import router as envelope_router
from .routes_monetization import router as monetization_router
from .routes_simulation import router as simulation_router
from .routes_flywheel import router as flywheel_router
from .routes_tenants import router as tenants_router
from .routes_audit import router as audit_router
from .routes_commands import router as commands_router
from .routes_edge import public_router as edge_public_router, protected_router as edge_protected_router
from .routes_settings import router as settings_router
from .routes_propagation import router as propagation_router
from .routes_sync import router as sync_router
from .routes_billing import router as billing_router
from .routes_reconciliation import router as reconciliation_router
from .routes_predictive import router as predictive_router
from .routes_sysinfo import router as sysinfo_router
from .routes_storage_accounts import router as storage_accounts_router
from .routes_object_storage import router as object_storage_router
from .routes_server_detail import router as server_detail_router
from .routes_tools import router as tools_router
from .routes_wireguard import router as wireguard_router
from .routes_frappe import router as frappe_router
from .routes_converter import router as converter_router
from .routes_webops import router as webops_router
from .routes_enrollment import router as enrollment_router
from .routes_traffic import router as traffic_router
from .routes_frothiq_nft import router as frothiq_nft_router
from .routes_anomaly import router as anomaly_router
from .routes_integrity import router as integrity_router
from .routes_recovery import router as recovery_router
from .routes_dev_reports import router as dev_reports_router
from .routes_analytics import router as analytics_router
from .routes_bing import router as bing_router
from .routes_vultr import router as vultr_router
from .routes_autoupdate import router as autoupdate_router
from .routes_mail_aliases import router as mail_aliases_router
from .routes_mail_quotas import router as mail_quotas_router
from .routes_apache_logs import router as apache_logs_router
from .routes_clamav import router as clamav_router
from .routes_disk_quotas import router as disk_quotas_router
from .routes_fail2ban import router as fail2ban_router
from .routes_bandwidth import router as bandwidth_router
from .routes_logrotate import router as logrotate_router
from .routes_packages import router as packages_router
from .routes_rbl import router as rbl_router
from .routes_wp_seo import router as wp_seo_router
from .routes_teleops import router as teleops_router
from .routes_mailman import router as mailman_router
from .routes_autoresponder import router as autoresponder_router
from .routes_ftp_users import router as ftp_users_router
from .routes_usermin import router as usermin_router
from .routes_traceroute import router as traceroute_router
from .routes_proftpd import router as proftpd_router
from .routes_domain_bandwidth import router as domain_bandwidth_router
from .routes_awstats import router as awstats_router
from .routes_themes import router as themes_router
from .routes_vhost import router as vhost_router
from .routes_universe import router as universe_router

# All control center routes under /api/v1/cc/
api_router = APIRouter(prefix="/api/v1/cc")
api_router.include_router(auth_router)
api_router.include_router(mfa_router)
api_router.include_router(dashboard_router)
api_router.include_router(defense_router)
api_router.include_router(policy_router)
api_router.include_router(license_router)
api_router.include_router(envelope_router)
api_router.include_router(monetization_router)
api_router.include_router(simulation_router)
api_router.include_router(flywheel_router)
api_router.include_router(tenants_router)
api_router.include_router(audit_router)
api_router.include_router(commands_router)
# Edge management routes (JWT protected, under /api/v1/cc/)
api_router.include_router(edge_protected_router)
# Portal settings (GET is public; write endpoints require super_admin)
api_router.include_router(settings_router)
# Threat propagation engine
api_router.include_router(propagation_router)
# Subscription + license state sync (read-only, ERPNext source of truth)
api_router.include_router(sync_router)
# Billing webhook receiver + state query + drift report
api_router.include_router(billing_router)
# Reconciliation engine — drift detection, correction, audit, edge ACK
api_router.include_router(reconciliation_router)
# Predictive sync — signal detection, staged contracts, accuracy metrics
api_router.include_router(predictive_router)
# ServOps — host system metrics (super_admin only)
api_router.include_router(sysinfo_router)
api_router.include_router(storage_accounts_router)
api_router.include_router(object_storage_router)
# ServOps — per-server structured detail panels
api_router.include_router(server_detail_router)
# ServOps — system tools (terminal, file manager, network tools)
api_router.include_router(tools_router)
# ServOps — WireGuard VPN management
api_router.include_router(wireguard_router)
# Frappe bench management (sites, apps, workers, scheduler)
api_router.include_router(frappe_router)
# Site Converter — WordPress/Joomla → Frappe migration engine
api_router.include_router(converter_router)
# WebOps — virtual server inventory and controlled management
api_router.include_router(webops_router)
# IP enrollment flow — enroll/start, enroll/complete, approve-ip
api_router.include_router(enrollment_router)
# IP Traffic Monitor — live feed and stats from gateway audit stream
api_router.include_router(traffic_router)
# FrothIQ NFT Defense Settings — service control, IP/port management, decommission
api_router.include_router(frothiq_nft_router)
# Anomaly detection — threat pattern events, acknowledge, scan trigger, stats
api_router.include_router(anomaly_router)
# Integrity score system — per-node and fleet-level 0–100 health scores
api_router.include_router(integrity_router)
# Rollback & Recovery Engine — node resets, IP demotions, stale cleanups
api_router.include_router(recovery_router)
# Dev Reports — Claude Code task-completion session reports
api_router.include_router(dev_reports_router)
# WebOps Analytics — Google Search Console (and future GA4) via service account
api_router.include_router(analytics_router)
# WebOps Analytics — Microsoft Bing Webmaster Tools via API key
api_router.include_router(bing_router)
# ServOps — Vultr cloud storage management (object storage + block volumes)
api_router.include_router(vultr_router)
# Auto-update engine — FrothIQ plugin and MC3 service deployment
api_router.include_router(autoupdate_router)
# Mail Alias & Forwarding Manager — Virtualmin alias CRUD
api_router.include_router(mail_aliases_router)
# Mail Quota Manager — per-mailbox disk quota read/write
api_router.include_router(mail_quotas_router)
# Per-Domain Apache Log Viewer
api_router.include_router(apache_logs_router)
# ClamAV Virus Scanner Management
api_router.include_router(clamav_router)
# Per-User & Per-Group Disk Quota Management
api_router.include_router(disk_quotas_router)
# Fail2ban Configuration & Jail Manager
api_router.include_router(fail2ban_router)
# Bandwidth Monitoring per Network Interface
api_router.include_router(bandwidth_router)
# Logrotate Rule Editor
api_router.include_router(logrotate_router)
# Package Manager — apt install/remove/search
api_router.include_router(packages_router)
# RBL / DNSBL — IP blacklist reputation checks
api_router.include_router(rbl_router)
# WordPress SEO & Plugin Compliance — WP-CLI based
api_router.include_router(wp_seo_router)
# TeleOps — multi-tenant telephony console (Phase A skeleton; CRUD in A.3/A.4)
api_router.include_router(teleops_router)
# MailMan — operator inventory of mailboxes across all Virtualmin domains
api_router.include_router(mailman_router)
# Email Autoresponder & Vacation Manager — per-mailbox autoreply CRUD
api_router.include_router(autoresponder_router)
# FTP / SFTP User Manager — virtualmin FTP user CRUD across all domains
api_router.include_router(ftp_users_router)
# Usermin Configuration — read-only status + config snapshot of usermin.service
api_router.include_router(usermin_router)
# FrothIQ traceroute attacker analysis — enriches hops with PTR / hosting / suspicious classification
api_router.include_router(traceroute_router)
# ProFTPD Global Configuration — service state, selected directives, controlled restart
api_router.include_router(proftpd_router)
# Per-Domain Bandwidth Reports — Apache access log aggregation per virtualmin domain
api_router.include_router(domain_bandwidth_router)
# AWStats per-domain web analytics — parses /etc/awstats/awstats.*.conf data files
api_router.include_router(awstats_router)
# Theme system — operator-editable CSS variable bundles, one active at a time
api_router.include_router(themes_router)
api_router.include_router(vhost_router)
api_router.include_router(universe_router)

# Public edge registration (no JWT — separate prefix /api/v1/edge/)
# This is mounted directly on the FastAPI app in main.py
edge_registration_router = edge_public_router

__all__ = ["api_router", "edge_registration_router"]
