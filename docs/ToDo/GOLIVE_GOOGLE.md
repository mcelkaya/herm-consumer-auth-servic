# Go-Live Guide — Google Sign-In

How to take Google Sign-In from "Testing" to production for the herm app. The
good news up front: because herm uses Sign in with Google **for authentication
only** (scopes `openid`, `email`, `profile` — all non-sensitive), you do **not**
need Google's heavyweight app verification (the YouTube-demo, security-
assessment process that sensitive/restricted scopes require). You need
**Brand Verification** and to **publish** the project. That's a much shorter
path.

---

## Where you are now

Your OAuth project is in **Testing** publishing status. In Testing:
- Only the up-to-100 Google accounts listed as **test users** can sign in.
- That's fine for staging — you can fully test the flow before publishing.
- Branding (name/logo) isn't shown on a polished consent screen yet.

## What "live" requires

Two things, in order:

### 1. Prerequisites (have these ready)
- A **Privacy Policy URL** and **Terms of Service URL**, publicly reachable over
  HTTPS (e.g. `https://app.herm.io/privacy`, `https://app.herm.io/terms`).
- All domains used anywhere in the consent config — home page, privacy, ToS,
  authorized JavaScript origins, redirect URIs — must be **verified domains**.
  Verify them in Google Search Console under the same Google account that owns
  the Cloud project. Your domains: `app.herm.io`, `wizard.herm.io`,
  `ministry.herm.io`.
- App name, support email, and a square app **logo** (PNG, 120×120+).

### 2. Publish + Brand Verification
1. Google Cloud Console → **Google Auth Platform → Audience**.
2. Confirm the app is **External**, then click **Publish app** to move the
   publishing status to **In production**. For non-sensitive scopes, users with
   any Google account can now sign in.
3. Go to **Branding**. Fill in app name, logo, support email, the privacy and
   ToS URLs, and the authorized domains.
4. If the console offers a **Submit for verification** action for branding,
   submit it. Brand verification is what lets your name and logo appear on the
   Google consent screen (instead of an "unverified app" notice).

> Authentication itself works in production once published, even while brand
> verification is pending — the verification governs how your branding is
> displayed, not whether sign-in functions, for non-sensitive scopes.

### Timeline
Brand verification typically lands within a few days but can take up to a couple
of weeks. There's no fee. If Google emails questions, respond promptly — an
unanswered request stalls the review.

---

## Recommended project hygiene

Google recommends **separate projects for testing and production**. If you have
one project doing both, consider creating a dedicated production project with
its own OAuth clients, so your test clients and test-user list don't sit inside
the project you submit for verification. If you do this, the production client
IDs change — update `GOOGLE_CLIENT_IDS` in the auth-service env accordingly.

---

## What the backend needs at go-live

Nothing structural. Just make sure `GOOGLE_CLIENT_IDS` holds the **production**
web + iOS + Android client IDs (not test-project ones). No redeploy of code is
required beyond the env value change.

## Checklist

- [ ] Privacy Policy + ToS URLs live on HTTPS
- [ ] `app.herm.io` (+ others) verified in Search Console under the project owner
- [ ] App name, logo, support email set on Branding
- [ ] Publishing status = **In production** (Publish app clicked)
- [ ] Brand verification submitted (if prompted)
- [ ] `GOOGLE_CLIENT_IDS` env = production client IDs
- [ ] Official "Sign in with Google" button styling used in the app
