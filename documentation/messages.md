# Messages

A save, an error or a refusal leaves a **message** that survives the redirect
and is shown once. The header is `message.h`; the page shows it with the
`messages` widget (layouts.md).

## Where it is kept, and why

The queue is **server-side, per session**. A message is one record of the
store's environment scope (the scope that holds environment-local settings, so
it is never in a snapshot, a restore, a revision or an export), under a key made
of the tenant, a keyed digest of the session and a sequence number. The value is
sealed with AES-256-GCM under a key derived from the tenant keyring for the
purpose `message`; what the seal authenticates is the version, the tenant, the
session digest, the sequence number and the expiry.

A signed cookie was the other candidate, and it was not chosen:

- **Once.** A cookie is the client's, and nothing the server holds says it was
  shown. A client that keeps the old cookie shows the message again, and so does
  a second tab that sent it. A server-side record is deleted by the page that
  claims it, in one write of a scope whose writes are serialised, so two
  requests of one session cannot both be shown the same message.
- **A lost response.** The claim is committed before the response is sent, so a
  response that never arrives shows nothing a second time. A render that fails
  after the claim puts the messages back, so a message that was never drawn is
  not lost.
- **Secrets.** The text is never in the cookie, and so never in a log of
  cookies, a proxy, or the browser.

What the server-side record costs is a write to post and a write to claim. Only
a signed-in session has a queue (a visitor has no session to bind a message
to), and a page claims only when it draws the `messages` widget.

## The session

`gdefcore_message_bind()` binds the session token to a request once the token is
shown to be live for the tenant (a made-up, damaged, expired or other tenant's
token binds nothing). The token itself is never stored: the record's key holds
a digest of it made with a key from the keyring, so a store reader cannot tell
whose queue a record is in, or make a key for one. Binding keeps two derived keys
on the request, wiped when the request is destroyed.

A message is for the session it was left, not the account: a second sign-in of
the same account is a different session and is shown nothing of the first's.

## Lifetime and size

A message waits `GDEFCORE_MESSAGE_LIFE` seconds (ten minutes), and never past
the session's own expiry. An expired record is dropped by the next post or claim
of that session and shows nothing. A session holds
`GDEFCORE_MESSAGE_QUEUE_MAX` messages; posting another drops the oldest. A text
is at most `GDEFCORE_MESSAGE_TEXT_MAX` bytes.

## What a record that fails to open does

A record that was altered, moved to a different session's queue or another tenant's,
put under another sequence number, or written by something else, does not open.
It shows nothing and is deleted by the claim that finds it.

## Text

A message is text. The widget prints it through the render layer, which escapes
it, so `<script>` shows as text. A message should carry nothing the actor does
not already see, and none is logged.

## A page that draws a queue

What the page shows depends on the queue, so a request that drew the widget with
a bound session is marked uncacheable (`gdefcore_request_cacheable()`). A visitor's
page is not.
