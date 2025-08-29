# SOC challenge deployment plan

### Why We’re Doing This

Right now, bits of personal data (like phone numbers, UPI IDs, addresses) can sneak into our logs and APIs. If attackers get hold of those logs, they can commit fraud. That’s a big risk.

So we’re putting a guardian layer in place that will automatically mask sensitive info before it goes anywhere unsafe.

---

### How It Fits Into Our System

Think of it like airport security:

* Before any passenger (data) enters the airport (our system), they go through a scanner (our detector).
* If they’re carrying something dangerous (PII), it gets taken away (redacted).
* Only safe passengers (clean data) make it to the gate (our apps and storage).

---

### Where We’ll Put It

We’re setting up this “scanner” in three key places:

1. **At the Entrance (APIs / Gateways)**

   * Every request coming into our system gets checked.
   * If it has PII, we mask it right there.

2. **Inside the Apps (Backend Services)**

   * When apps log stuff, we run it through our redactor first.
   * This way, engineers don’t need to remember — it’s automatic.

3. **Before Data Storage (Log Pipelines)**

   * Any log going into storage systems (like Splunk, ELK, Kafka) gets scanned again.
   * So even if something slipped earlier, we catch it before it settles.

---

### How We’ll Deploy

* We’ll bundle the redactor into a small container (like a mini service).
* Then we’ll run it next to our apps or in front of our APIs.
* That way, it works silently in the background without needing every team to rewrite code.

---

### What We’ll Measure

* How often we’re catching PII.
* How fast we’re doing it (shouldn’t slow things down noticeably).
* If we ever miss something (we’ll sample logs to double-check).

---

### Step-by-Step Rollout

1. Test in one app (pilot) → make sure accuracy and speed are good.
2. Expand to all APIs → so everything coming in is safe.
3. Finally, add to log storage → so even legacy apps can’t leak data.

---

### The End State

* No more personal data in raw logs.
* APIs can’t accidentally leak sensitive stuff.
* Fraud risks from leaked info drop drastically.
* Teams don’t need to change their code much — protection is “always on.”

---
