# Go-Live Guide — Sign in with Apple

Sign in with Apple is the simplest of the three to take live: there is **no
separate Apple "verification" or token-approval process**. Once the capability
is enabled on your App ID and the app is built with a matching provisioning
profile, identity tokens work. The only real "gate" is standard **App Store
review** when you ship the app.

---

## Where you are now

You've created the App ID `io.herm.mobile` (Team ID `STNJ32J4MC`). To be live
you need: the **Sign In with Apple capability enabled** on that App ID, the
native app configured for it, and — for full account-lifecycle support — a
Sign in with Apple **key** for server-to-server notifications.

## What "live" requires

### 1. Enable the capability (App ID)
1. Apple Developer → Certificates, Identifiers & Profiles → **Identifiers** →
   `io.herm.mobile`.
2. In **Capabilities**, tick **Sign In with Apple** → **Save**.
3. Because you changed capabilities, **regenerate the provisioning profile** so
   the entitlement is included in builds (EAS regenerates this for you on the
   next build when credentials are managed).

### 2. Native app config
- `app.json` already has `ios.bundleIdentifier: "io.herm.mobile"` and
  `usesAppleSignIn` should be true (the `expo-apple-authentication` plugin sets
  the entitlement).
- Show the official Sign in with Apple button per Apple's Human Interface
  Guidelines wherever you show Google/Facebook buttons.

### 3. App Store review rules you must satisfy
- **Guideline 4.8 (Login Services):** if your app offers third-party sign-in
  (Google, Facebook), you must also offer an equivalent privacy-focused option.
  Sign in with Apple qualifies. Since you're shipping all three, you comply —
  just make sure the Apple option is actually present and working on iOS.
- **Guideline 5.1.1(v) (Account deletion):** if the app lets users create an
  account, it must let them **delete** their account from within the app. Make
  sure your settings screen has account deletion before submitting.

### 4. Sign in with Apple key (recommended, for lifecycle)
The basic identity-token verification herm does today doesn't need a key. But to
receive Apple's **server-to-server notifications** (e.g. the user disconnects
their Apple ID, deletes it, or revokes email relay forwarding) you should
configure one:
1. **Keys → +** → name it (e.g. "Herm SIWA"), enable **Sign in with Apple**,
   configure it for the primary App ID `io.herm.mobile`.
2. Download the `.p8` **once** (non-recoverable); note the **Key ID** and your
   **Team ID** (`STNJ32J4MC`).
3. Store these securely for when you add the notifications endpoint. (Out of
   scope for the current build; noted so you capture the key now while you're in
   the console.)

### 5. Email relay (if users pick "Hide My Email")
If you want to email users who chose Hide My Email, register and verify your
sending domains/addresses under **Sign in with Apple for Email Communication**
(Services → Configure → email sources). Not required for login to work.

### Timeline
Capability + build is immediate. The only wait is normal **App Store review**
(typically ~24–48h per submission). TestFlight lets you validate the live Apple
flow before public release.

---

## What the backend needs at go-live

Nothing structural. Confirm `APPLE_CLIENT_IDS=io.herm.mobile` (add your web
Services ID later only if you add web Sign in with Apple). The backend already
verifies Apple identity tokens against Apple's public keys and handles the
"Hide My Email" relay and first-login-only email behavior.

## Checklist

- [ ] Sign In with Apple capability enabled on `io.herm.mobile` + profile regenerated
- [ ] `usesAppleSignIn` true; official Apple button shown on iOS
- [ ] In-app account deletion present (Guideline 5.1.1(v))
- [ ] Apple option offered alongside Google/Facebook (Guideline 4.8)
- [ ] SIWA key (.p8 + Key ID + Team ID) saved for future server notifications
- [ ] `APPLE_CLIENT_IDS=io.herm.mobile`
- [ ] Validated on TestFlight before public release
