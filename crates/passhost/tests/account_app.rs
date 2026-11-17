mod common;

use common::*;

/// The account app's signed-in pages (account settings) call Proton account
/// endpoints passhost has no feature for; they must answer with empty data in
/// the shape the client reads, or the pages show "Something went wrong".
#[tokio::test]
async fn account_dashboard_endpoints() {
    let s = server().await;
    let c = Client::signup(&s, &unique("dash"), "pw").await;

    let checks: &[(&str, &str)] = &[
        ("account/v1/access/incoming", "DelegatedAccesses"),
        ("account/v1/access/outgoing", "DelegatedAccesses"),
        ("contacts/v4/contacts/emails", "ContactEmails"),
        ("core/v4/groups/members/internal", "Memberships"),
        ("core/v4/users/invitations", "UserInvitations"),
        ("core/v5/entitlements", "UserEntitlements"),
        ("payments/v6/plans/entitlements", "Plans"),
        ("payments/v5/invoices", "Invoices"),
        ("payments/v5/account/billing-information", "BillingAddress"),
        ("oauth-token/v1/tokens", "Tokens"),
        ("account/v4/breaches", "Breaches"),
        ("core/v4/logs/auth", "Logs"),
        ("core/v4/system/config", "Config"),
    ];
    for (path, field) in checks {
        let body = c.get(path).await;
        assert_eq!(body["Code"], 1000, "{path}: {body}");
        assert!(!body[*field].is_null(), "{path} lacks {field}: {body}");
    }
    let sub = c.get("payments/v6/subscription/latest").await;
    assert!(sub["Subscription"].is_null(), "{sub}");

    // v6 event loops: a stable ID and never any changes.
    for product in ["core", "mail", "contacts", "calendar"] {
        let latest = c.get(&format!("{product}/v6/events/latest")).await;
        let id = latest["EventID"].as_str().unwrap().to_string();
        let next = c.get(&format!("{product}/v6/events/{id}")).await;
        assert_eq!(next["EventID"], id);
        assert_eq!(next["More"], false);
    }

    // Settings fields the settings pages read.
    let settings = c.get("core/v4/settings").await;
    for field in ["Mnemonic", "ProductDisabled", "OrganizationPolicy", "UsedClients"] {
        assert!(!settings["UserSettings"][field].is_null(), "settings lack {field}: {settings}");
    }
    assert_eq!(settings["UserSettings"]["HighSecurity"]["SummaryEmail"], 0);
}
