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
        .route("/feature/v2/frontend/{*rest}", get(feature_flags))
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
        .route("/data/v1/stats/multiple", post(empty))
        .route("/core/v4/reports/bug", post(empty))
        .route("/core/v4/metrics", post(empty))
        .route("/core/v4/images/logo", get(empty))
        .route("/core/v4/users/apps", get(|| async { ok(json!({ "Apps": ["pass"] })) }))
        .route("/core/v4/checklist/{*rest}", get(|| async { ok(json!({ "Items": [], "CreatedAt": 0, "ExpiresAt": 0, "Visible": false, "Display": "Hidden" })) }))
        .route("/account/v1/onboarding", get(empty).put(empty))
        .route("/core/v4/settings/telemetry", put(empty))
}
