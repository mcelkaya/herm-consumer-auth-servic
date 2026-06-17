# Go-Live Guide — Meta (Facebook) Login

How to take Facebook Login from a development-mode app to live production for
herm. Meta is the most paperwork-heavy of the three because of **Business
Verification**, so start this one early.

---

## Where you are now

Your Meta app is in **Development** mode. In Development:
- Only people with a **Role** on the app (Admins, Developers, Testers) can log
  in, and only they receive `email`. Great for staging; invisible to real users.
- `email` and `public_profile` are the only permissions herm needs, and Meta
  grants these to every app by default — so you are **not** chasing exotic
  permission approvals. The gates are Business Verification and switching to
  Live mode.

## What "live" requires

### 1. Business Verification (start here — it's the long pole)
Meta increasingly requires Business Verification to retain access to even basic
login data (email / public profile) for apps serving the public.

1. In your **Meta Business portfolio**, open the **Security Center** and click
   **Start verification**.
2. Provide your legal business details for **HERMIO LTD**: registered name,
   address, phone, and website (`https://app.herm.io`, must be live + HTTPS).
3. Verify your connection to the business via one of: a **business-domain
   email** (e.g. `you@herm.io` — personal `@gmail.com`/`@yahoo.com` addresses
   are **not** accepted), phone, or domain verification.
4. Meta matches you against public business records or asks for documents
   (incorporation certificate, etc.).

> Because you'll verify with a business-domain email, make sure you have a
> mailbox on `herm.io` (or whichever domain you register) before starting.

### 2. App prerequisites for Live mode
- **Privacy Policy URL** (required to flip to Live).
- **Data Deletion** instructions URL or a Data Deletion Callback (Meta requires
  a way for users to request deletion of data your app obtained).
- App **icon**, **category**, and display name set under Settings → Basic.
- App Domains and the iOS Bundle ID (`io.herm.mobile`) / Android package
  (`io.herm.mobile`) + key hash configured under the platform settings.

### 3. Switch to Live
Once business verification is approved and the prerequisites are in place,
toggle the app from **Development** to **Live** at the top of the App Dashboard.
Real users can now log in and receive their email.

### 4. App Review — only if prompted
For consumer Facebook Login with just `email` + `public_profile`, you typically
won't need a full permission review. If Meta does request review for your data
use, it will ask for a **screencast** demonstrating the exact login flow a user
sees, and expect that recording to show the permission being used. Be ready to
record the herm login screen → Facebook prompt → return-to-app flow. Reviews can
take a few iterations, so leave buffer.

### 5. Annual upkeep
Meta may require a **Data Use Checkup** annually and re-confirmation of
permissions; calendar it so access doesn't lapse.

### Timeline
Business Verification can take anywhere from a day to a couple of weeks
depending on document matching. The Live toggle is instant once prerequisites
are met.

---

## What the backend needs at go-live

Nothing structural. Confirm `FACEBOOK_APP_ID` is your production app id and
`FACEBOOK_APP_SECRET` (in SSM/Secrets Manager) is the matching secret. The
backend treats Facebook emails as verified by default
(`FACEBOOK_EMAIL_VERIFIED_DEFAULT=true`); leave that unless you want to force
Facebook links through the settings page.

## Checklist

- [ ] Business portfolio created; **Business Verification** submitted/approved
- [ ] Business-domain email mailbox exists (for verification)
- [ ] Privacy Policy URL live
- [ ] Data deletion instructions/callback configured
- [ ] iOS bundle id + Android package & key hash set on the app's platforms
- [ ] App icon, category, display name set
- [ ] App toggled to **Live**
- [ ] `FACEBOOK_APP_ID` / `FACEBOOK_APP_SECRET` = production values
- [ ] Screencast ready in case review is requested
