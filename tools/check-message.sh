#!/bin/sh
#
# The message queue gate (site admin story 9): a message is shown once, to the
# session it was left and to no other; a record that was altered or moved shows
# nothing; the text is escaped; a message is not shown past its lifetime; a made
# up session has no queue; the queue is bounded; and a page that drew a queue is
# not cached.
#
# Runs the Message tests on the real tree, then plants each defect in a COPY of
# the source by an exact text edit and requires the named test to fail:
#
#   stale-object                     the first plant, rebuilt: shows a plant is built
#   message-shown-twice              Message.AMessageIsShownOnceAndNeverToAnotherSession
#   message-shown-to-another-session Message.AMessageIsShownOnceAndNeverToAnotherSession
#   forged-message-accepted          Message.AForgedOrMovedMessageIsRejectedAndShowsNothing
#   message-text-unescaped           Message.TextIsEscapedAndNeverMarkup
#   expired-message-shown            Message.AMessageNotShownByItsExpiryIsDropped
#   made-up-session-binds            Message.AVisitorAndAMadeUpSessionHaveNoQueue
#   queue-unbounded                  Message.TheQueueIsBoundedAndTheTextIsLimited
#   queue-page-cacheable             Message.TheKeysAreWipedWithTheRequestAndAPageWithAQueueIsNotCacheable
#
# Every test has a control (the session it was left DOES see it, the unaltered
# record DOES open, the text at the limit IS accepted), so a plant turning one
# red is a test seeing the defect, not a build failure.
#
# Usage: check-message.sh <make> <build-dir> [make args]

set -u

. "$(dirname "$0")/plant-load.sh"
plant_setup "$@"

plant_control testMessage 'Message.*'

MSG=src/message/message.c

ONCE_OLD='    rc = map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1, l[i].key,
        l[i].key_len, &deleted));'
ONCE_NEW='    rc = ok ? (deleted = 1, GDEFCORE_OK)
            : map_stor(gdefstor_record_delete(write, kNs, sizeof kNs - 1, l[i].key,
                  l[i].key_len, &deleted));'

plant_stale stale-object $MSG testMessage \
  'Message.AMessageIsShownOnceAndNeverToAnotherSession' \
  "$ONCE_OLD" "$ONCE_NEW"

# Plant 1: a message that was claimed stays in the queue, so the next page shows
# it again.
plant message-shown-twice $MSG testMessage \
  'Message.AMessageIsShownOnceAndNeverToAnotherSession' \
  "$ONCE_OLD" "$ONCE_NEW"

# Plant 2: the session is in neither the record's key nor what the seal
# authenticates, so every session of the tenant reads one queue.
plant message-shown-to-another-session $MSG testMessage \
  'Message.AMessageIsShownOnceAndNeverToAnotherSession' \
  '  to_hex(out + at, box->digest, kDigest);
  at += kDigest * 2;' \
  '  memset(out + at, '"'"'0'"'"', kDigest * 2);
  (void)box;
  at += kDigest * 2;' \
  '  memcpy(aad + at, box->digest, kDigest);
  at += kDigest;' \
  '  memset(aad + at, 0, kDigest);
  (void)box;
  at += kDigest;'

# Plant 3: the record is stored as it is and read back without the seal being
# checked, so an altered or moved record is taken.
plant forged-message-accepted $MSG testMessage \
  'Message.AForgedOrMovedMessageIsRejectedAndShowsNothing' \
  '  wipe(plain, plain_n);
  free(plain);
  free(aad);
  if (rc != GDEFCORE_OK) {
    free(rec);' \
  '  memcpy(rec + kHead, plain, plain_n);
  wipe(plain, plain_n);
  free(plain);
  free(aad);
  if (rc != GDEFCORE_OK) {
    free(rec);' \
  '  ok = from_gsec(gsec_aes_gcm_decrypt(box->key, kKey, rec + 9, kNonce, aad, aad_n,
           rec + kHead, plain_n, plain, rec + kHead + plain_n, kTag)) == GDEFCORE_OK;' \
  '  memcpy(plain, rec + kHead, plain_n);
  ok = 1;'

# Plant 4: the text is handed to the template as trusted, which it prints as it
# is.
plant message-text-unescaped src/render/render.c testMessage \
  'Message.TextIsEscapedAndNeverMarkup' \
  '      lr = nav_text(d, map, "text", m.text, m.text_len);' \
  '      GLTANG_ValueRef raw;
      lr = gltang_value_string(d, m.text, m.text_len,
          GLTANG_UNICODE_STRING_TYPE_TRUSTED, &raw);
      if (lr == GLTANG_OK) {
        lr = gltang_value_map_set(d, map, "text", 4,
            GLTANG_UNICODE_STRING_TYPE_HTML_ATTRIBUTE, raw);
      }'

# Plant 5: a claim shows a message past its expiry.
plant expired-message-shown $MSG testMessage \
  'Message.AMessageNotShownByItsExpiryIsDropped' \
  '    if (ok && deleted && now >= 0 && exp > (uint64_t)now) {' \
  '    if (ok && deleted && (now >= 0 || now < 0)) {'

# Plant 6: a token that is not a live session of the tenant binds all the same.
plant made-up-session-binds $MSG testMessage \
  'Message.AVisitorAndAMadeUpSessionHaveNoQueue' \
  '  if (rc != GDEFCORE_OK) {
    return GDEFCORE_ERR_INVALID;
  }
  box = (Mailbox *)calloc(1, sizeof *box);' \
  '  if (rc != GDEFCORE_OK) {
    expiry = UINT64_MAX;
  }
  box = (Mailbox *)calloc(1, sizeof *box);'

# Plant 7: the oldest message is not dropped to make room.
plant queue-unbounded $MSG testMessage \
  'Message.TheQueueIsBoundedAndTheTextIsLimited' \
  '  for (i = 0; rc == GDEFCORE_OK && i < n && live >= GDEFCORE_MESSAGE_QUEUE_MAX; i++) {' \
  '  for (i = 0; rc == GDEFCORE_OK && i < n && 0 && live >= GDEFCORE_MESSAGE_QUEUE_MAX; i++) {'

# Plant 8: a page that drew a queue is left cacheable.
plant queue-page-cacheable src/render/render.c testMessage \
  'Message.TheKeysAreWipedWithTheRequestAndAPageWithAQueueIsNotCacheable' \
  '    msgs = NULL;
  } else {
    gdefcore_request_mark_uncacheable(request);
  }' \
  '    msgs = NULL;
  } else {
    (void)0;
  }'

plant_finish
