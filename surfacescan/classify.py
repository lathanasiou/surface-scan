"""Classify each host as own-infra / third-party-saas / suspicious.

Third-party SaaS targets are recorded but should NOT be port/vuln scanned —
they are someone else's servers. Suspicious covers dangling CNAMEs and
private IPs published in public DNS.
"""
from __future__ import annotations

from .models import HostResult

# CNAME suffixes that indicate a THIRD-PARTY SaaS PRODUCT — someone else's
# service hosting your content (not a server you administer, and not a platform
# where you deploy your own code). These are recorded but NOT probed: the tech
# found on them is the vendor's, not yours.
#
# NOTE: deploy-your-own-code platforms (Vercel, Netlify, Heroku, Render, Fly,
# Firebase, GitHub/GitLab Pages, Cloudflare Pages) are deliberately NOT here —
# those host YOUR app and should be probed; cdn.py labels them as the edge.
#
# Extend freely — grouped by category for readability.
SAAS_SUFFIXES = [
    # --- Website / landing-page builders ---
    "webflow.io", "webflow.com", "wixdns.net", "wixsite.com", "wix.com",
    "squarespace.com", "weebly.com", "weeblysite.com", "strikingly.com",
    "strikinglydns.com", "carrd.co", "framer.app", "framer.website",
    "editorx.io", "duda.co", "dudaone.com", "jimdo.com", "ucraft.net",
    "tilda.ws", "tilda.cc", "webnode.com", "mozello.com",
    # --- E-commerce platforms ---
    "myshopify.com", "shopify.com", "bigcommerce.com", "mybigcommerce.com",
    "ecwid.com", "bigcartel.com", "volusion.com", "storenvy.com",
    # --- CMS / managed-site hosts ---
    "wpengine.com", "wpenginepowered.com", "pantheonsite.io", "kinsta.cloud",
    "wordpress.com", "wpcomstaging.com", "ghost.io", "squarespace-cdn.com",
    "myshopify.io", "cargo.site", "contentful.com",
    # --- Status pages ---
    "statuspage.io", "status.io", "uptimerobot.com", "betteruptime.com",
    "betterstack.com", "instatus.com", "freshstatus.io", "statuscast.com",
    "hund.io", "sorryapp.com", "cachethq.io",
    # --- Support / helpdesk / chat ---
    "zendesk.com", "zdassets.com", "freshdesk.com", "freshworks.com",
    "helpscoutdocs.com", "helpscout.net", "intercom.io", "intercom.help",
    "gorgias.com", "kayako.com", "groovehq.com", "helpdocs.io",
    "zohodesk.com", "zohohost.com", "tawk.to", "crisp.help", "gladly.com",
    "front.com", "livechatinc.com", "drift.com",
    # --- Marketing / landing / forms / CRM ---
    "hubspot.net", "hubspotusercontent.com", "hs-sites.com", "hsforms.net",
    "marketo.com", "mktoweb.com", "pardot.com", "unbounce.com", "ubembed.com",
    "instapage.com", "pageclip.co", "leadpages.co", "leadpages.net",
    "clickfunnels.com", "mailchimp.com", "list-manage.com", "klaviyo.com",
    "activehosted.com", "salesforce.com", "force.com", "desk.com",
    "typeform.com", "jotform.com", "wufoo.com", "formstack.com",
    "surveymonkey.com", "qualtrics.com",
    # --- Scheduling / booking ---
    "calendly.com", "youcanbook.me", "acuityscheduling.com", "cal.com",
    "savvycal.com", "setmore.com",
    # --- Docs / knowledge base / wikis ---
    "readthedocs.io", "readthedocs.org", "gitbook.io", "gitbook.com",
    "readme.io", "readme.com", "document360.io", "notion.site", "notion.so",
    "helpjuice.com", "archbee.io", "mintlify.app", "mintlify.dev",
    "atlassian.net", "confluence.com",
    # --- Developer / community / feedback ---
    "discourse.group", "discourse.org", "circle.so", "canny.io",
    "uservoice.com", "featureupvote.com", "frill.co", "nolt.io",
    # --- Email / transactional (appear in DNS, not web apps) ---
    "sendgrid.net", "mailgun.org", "mandrillapp.com", "sparkpostmail.com",
    "postmarkapp.com", "mailersend.net", "sendinblue.com", "brevo.com",
    # --- Video / media hosting ---
    "wistia.com", "wistia.net", "vimeo.com", "vidyard.com", "sproutvideo.com",
    # --- Scheduling of CI / misc SaaS that sometimes gets a CNAME ---
    "pages.github.com", "githubusercontent.com",
    "zohocommerce.com", "freshsales.io",
]


def classify(host: HostResult) -> None:
    chain = [c.lower() for c in host.cname_chain]

    if host.liveness == "dangling" or any("dangling" in n for n in host.dns_notes):
        host.classification = "suspicious"
        return
    if any("private/non-routable" in n for n in host.dns_notes):
        host.classification = "suspicious"
        return

    for c in chain:
        for suffix in SAAS_SUFFIXES:
            if suffix in c:
                host.classification = "third-party-saas"
                return

    # CDN in front but no SaaS target -> still your app (CDN is just edge)
    if host.resolved_ips or host.cname_chain:
        host.classification = "own-infra"
    else:
        host.classification = "unknown"
