//! Small endpoints the official clients call that have no real meaning on a
//! self-hosted server: feature flags, payments, telemetry, notifications...

use axum::{
    Json, Router,
    routing::{get, post, put},
};
use serde_json::{Value, json};

use crate::{
    app::AppState,
    util::{ok, ok_empty},
};

/// Clients send crash reports here (Sentry envelopes). We don't forward them
/// anywhere, but log the error messages: they are the quickest way to see
/// which response a client could not handle.
async fn sentry_report(body: axum::body::Bytes) -> Json<Value> {
    let text = String::from_utf8_lossy(&body);
    for line in text.lines() {
        if let Ok(v) = serde_json::from_str::<Value>(line)
            && let Some(values) = v["exception"]["values"].as_array()
        {
            for e in values {
                let frames = e["stacktrace"]["frames"]
                    .as_array()
                    .map(|f| {
                        f.iter()
                            .rev()
                            .take(6)
                            .filter_map(|fr| fr["function"].as_str())
                            .collect::<Vec<_>>()
                            .join(" < ")
                    })
                    .unwrap_or_default();
                tracing::warn!(
                    "client error report: {}: {} [{}]",
                    e["type"].as_str().unwrap_or("?"),
                    e["value"].as_str().unwrap_or("?"),
                    frames
                );
            }
        }
    }
    ok_empty()
}

/// Website logos are fetched from Proton's logo service; we have none, and a
/// 404 makes clients fall back to their generic icon.
async fn no_logo() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_FOUND
}

async fn empty() -> Json<Value> {
    ok_empty()
}

async fn feature_flags() -> Json<Value> {
    // Unleash-style frontend toggles. Empty means clients use their defaults.
    ok(json!({ "toggles": [] }))
}

async fn features() -> Json<Value> {
    ok(json!({ "Features": [] }))
}

async fn plans() -> Json<Value> {
    ok(json!({ "Plans": [], "DefaultPlans": [] }))
}

/// No plans are sold here; clients fall back to their built-in free plan.
async fn plans_default() -> axum::response::Response {
    use axum::response::IntoResponse;
    crate::error::ApiError::new(
        axum::http::StatusCode::NOT_FOUND,
        crate::error::code::NOT_FOUND,
        "No default plan",
    )
    .into_response()
}

/// Chargebee configuration; empty because payments are disabled.
async fn web_configuration() -> Json<Value> {
    ok(json!({ "Site": "", "PublishableKey": "", "Domain": "" }))
}

/// Referrals are a Proton promotion; reported as not eligible.
async fn no_referrals() -> crate::error::ApiError {
    crate::error::ApiError::not_found("Referrals")
}

async fn billing_information() -> Json<Value> {
    ok(json!({
        "BillingAddress": { "CountryCode": "", "State": null, "ZipCode": null },
        "VatId": null,
    }))
}

/// A fixed event ID with no changes: these event loops only exist for Proton
/// products (mail, calendar, contacts) that passhost does not implement.
async fn v6_events() -> Json<Value> {
    ok(json!({ "EventID": "passhost-v6", "More": false, "Refresh": false }))
}

async fn subscription() -> Json<Value> {
    ok(json!({ "Subscription": null, "UpcomingSubscription": null }))
}

async fn payment_status() -> Json<Value> {
    ok(json!({ "CountryCode": "US", "State": null, "ZipCode": null,
               "VendorStates": { "Card": false, "Paypal": false, "Apple": false, "Cash": false, "Bitcoin": false, "InApp": false } }))
}

async fn methods() -> Json<Value> {
    ok(json!({ "PaymentMethods": [] }))
}

async fn mail_settings() -> Json<Value> {
    ok(
        json!({ "MailSettings": { "DisplayName": "", "Signature": "", "Theme": "", "AutoSaveContacts": 0,
        "ComposerMode": 0, "MessageButtons": 0, "ShowImages": 0, "ShowMoved": 0, "ViewMode": 0,
        "ViewLayout": 0, "SwipeLeft": 0, "SwipeRight": 0, "AlsoArchive": 0, "Hotkeys": 0,
        "Shortcuts": 0, "PMSignature": 0, "ImageProxy": 0, "NumMessagePerPage": 50,
        "DraftMIMEType": "text/html", "ReceiveMIMEType": "text/html", "ShowMIMEType": "text/html",
        "PGPScheme": 16, "PromptPin": 0, "Attach": 0, "Sign": 0, "StickyLabels": 0,
        "ConfirmLink": 1, "DelaySendSeconds": 0, "KT": 0, "FontSize": null, "FontFace": null,
        "SpamAction": null, "BlockSenderConfirmation": null, "HideRemoteImages": 0,
        "HideEmbeddedImages": 0, "HideSenderImages": 0, "AutoDeleteSpamAndTrashDays": null,
        "MobileSettings": null, "RightToLeft": 0, "AlmostAllMail": 0, "NextMessageOnMove": 0, "PageSize": 50 } }),
    )
}

async fn organization() -> Json<Value> {
    ok(json!({ "Organization": null }))
}

async fn members() -> Json<Value> {
    ok(json!({ "Members": [], "Total": 0 }))
}

async fn vpn_location() -> Json<Value> {
    ok(json!({ "IP": "", "Lat": 0, "Long": 0, "Country": "", "ISP": "" }))
}

async fn notifications() -> Json<Value> {
    ok(json!({ "Notifications": [] }))
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/feature/v2/frontend", get(feature_flags))
        .route("/feature/v2/frontend/{*rest}", get(feature_flags).post(empty))
        .route("/core/v4/features", get(features))
        .route("/core/v4/features/{*rest}", get(features).put(empty))
        .route("/payments/v4/plans", get(plans))
        .route("/payments/v5/plans", get(plans))
        .route("/payments/v4/subscription", get(subscription))
        .route("/payments/v5/subscription", get(subscription))
        .route("/payments/v4/status", get(payment_status))
        .route("/payments/v5/status", get(payment_status))
        .route("/payments/v4/methods", get(methods))
        .route("/payments/v5/methods", get(methods))
        .route("/payments/v4/subscription/latest", get(subscription))
        .route("/mail/v4/settings", get(mail_settings))
        .route("/core/v4/organizations", get(organization))
        .route("/core/v4/members", get(members))
        .route("/core/v4/members/me", get(members))
        .route("/vpn/v1/location", get(vpn_location))
        .route("/core/v4/notifications", get(notifications))
        .route("/data/v1/stats", post(empty))
        .route("/data/v1/telemetry", post(empty))
        .route("/data/v1/metrics", post(empty))
        .route("/payments/v4/plans/default", get(plans_default))
        .route("/payments/v5/plans/default", get(plans_default))
        .route("/payments/v5/web-configuration", get(web_configuration))
        .route("/data/v1/stats/multiple", post(empty))
        .route("/core/v4/reports/bug", post(empty))
        .route("/core/v4/reports/sentry/{*rest}", post(sentry_report))
        .route("/core/v4/metrics", post(empty))
        .route("/core/v4/images/logo", get(no_logo))
        .route("/core/v4/users/apps", get(|| async { ok(json!({ "Apps": ["pass"] })) }))
        .route("/core/v4/checklist/{*rest}", get(|| async { ok(json!({ "Items": [], "CreatedAt": 0, "ExpiresAt": 0, "Visible": false, "Display": "Hidden" })) }))
        .route("/account/v1/onboarding", get(empty).put(empty))
        .route("/core/v4/settings/telemetry", put(empty))
        // --- Account dashboard (account app's signed-in pages) ---
        // Proton features passhost does not have: answer "nothing here".
        .route("/account/v1/access/incoming", get(|| async { ok(json!({ "DelegatedAccesses": [] })) }))
        .route("/account/v1/access/outgoing", get(|| async { ok(json!({ "DelegatedAccesses": [] })) }))
        .route("/contacts/v4/contacts/emails", get(|| async { ok(json!({ "ContactEmails": [], "Total": 0 })) }))
        .route("/core/v4/groups/members/internal", get(|| async { ok(json!({ "Memberships": [] })) }))
        .route("/core/v4/users/invitations", get(|| async { ok(json!({ "UserInvitations": [] })) }))
        .route("/core/v4/referrals/info", get(no_referrals))
        .route("/core/v5/entitlements", get(|| async {
            ok(json!({ "UserEntitlements": [], "OrganizationEntitlements": [], "MemberEntitlements": [] }))
        }))
        .route("/payments/v6/plans/entitlements", get(|| async { ok(json!({ "Plans": [], "Addons": [] })) }))
        .route("/payments/v6/subscription/latest", get(|| async { ok(json!({ "Subscription": null })) }))
        .route("/payments/v5/account/billing-information", get(billing_information))
        .route(
            "/oauth-token/v1/tokens",
            get(|| async { ok(json!({ "Tokens": [] })) }),
        )
        .route(
            "/payments/v4/invoices",
            get(|| async { ok(json!({ "Invoices": [], "Total": 0 })) }),
        )
        .route(
            "/payments/v5/invoices",
            get(|| async { ok(json!({ "Invoices": [], "Total": 0 })) }),
        )
        // Dark-web breach monitoring needs a data source passhost lacks.
        .route(
            "/account/v4/breaches",
            get(|| async { ok(json!({ "Breaches": [], "Samples": [], "IsEligible": false, "Count": 0 })) }),
        )
        // Security log: passhost records no sign-in history.
        .route(
            "/core/v4/logs/auth",
            get(|| async { ok(json!({ "Logs": [], "Total": 0 })) }),
        )
        // Mail importer OAuth client IDs (Easy Switch): none configured.
        .route(
            "/core/v4/system/config",
            get(|| async {
                ok(json!({ "Config": {
                    "oauth.google.client_id": "",
                    "oauth.outlook.client_id": "",
                    "oauth.zoom.client_id": "",
                } }))
            }),
        )
        // v6 event loops of products passhost does not serve: never any changes.
        .route("/core/v6/events/latest", get(v6_events))
        .route("/core/v6/events/{id}", get(v6_events))
        .route("/mail/v6/events/latest", get(v6_events))
        .route("/mail/v6/events/{id}", get(v6_events))
        .route("/contacts/v6/events/latest", get(v6_events))
        .route("/contacts/v6/events/{id}", get(v6_events))
        .route("/calendar/v6/events/latest", get(v6_events))
        .route("/calendar/v6/events/{id}", get(v6_events))
}
