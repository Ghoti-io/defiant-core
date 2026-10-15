# Rendering

A page has one display. A display is a layout of regions plus an ordered
list of panes. The layout template declares its own region names. The
kernel does not. `main` and `side` belong to the base theme's
two-column template.

Tang runs each template. The host registers that call with a segment
scope. When the scope runs out, the bytes already written are the page,
and that partial page is success. There is no socket and no
thread-local template.

## Safe by default

Every value the host binds into a template (a field, a title, a body, a
summary, and any later request, path or setting value) is bound with the
`HTML_ATTRIBUTE` tag. A template prints it bare, `<%= title %>`, and the
value is inert in element text and in both quote styles of an attribute
(`"` and `'` become entities; non-ASCII is left as written). Forgetting a
call cannot leak. A literal in a template is trusted as it always was.

The tag methods keep working. `.html` retags a value as plain HTML, which
does not escape quotes, so it is for element text only. `.raw` turns the
encoding off, and an editable template that uses it needs the `unsafe`
marker. `.percent` and `.javascript` encode for a query string and for a
script string.

The post body is escaped text, not markup: it is printed like any other
value. There is no sanitizer and no way to publish rich HTML through the
built-in templates.

The layout then pastes a pane's already-rendered HTML. That paste is
the one trusted insertion, and the comment on it is the marker. It is
trusted because the pane was produced by a template whose own values
were tagged. It is not escaped a second time.

### url()

Every template can call `url(x)` to build an `href` or `src`. It
returns `x` when the scheme is `http`, `https` or `mailto`, or when `x`
is a relative reference: it starts with `/`, `?`, `#`, `./` or `../`, or
is a path with no `:` before its first `/`. Anything else gives `#`, and
so does an argument that is not a string. The comparison ignores case,
leading ASCII whitespace and control characters, and tab, line feed and
carriage return anywhere, which is what a browser ignores, so
` JaVa\tScript:x` is refused. A network-path reference (`//host`, and
`/\host`, which a browser reads the same way) is not relative here and
gives `#`. The result keeps the `HTML_ATTRIBUTE` tag, so it is still
escaped inside the attribute.

```
<a href="<%= url(link) %>">read</a>
```

### Script strings

No built-in template produces inline `<script>` content. A value that
goes inside a script string must use the explicit `.javascript` form, and
the strict content security policy is the backstop. There is no linter for
this.

## Choosing a display

`/` selects the front-page display and does not consult the route
chain. Any other path is resolved as a form path. A resolved public id
of type `site.post` selects the post display. Anything else, including
a path that does not resolve, writes no bytes. A request that may not
read the entity gets that same error.

Render reads the published projection. A view lists through the access
filter and does not read revision documents. A draft has no published
row, so it is absent.

## Summary

The recent-posts pane prints a summary of each post, newest first, at
most five.

1. A non-empty summary is used as written.
2. Otherwise, if the body contains `<!--break-->`, the summary is the
   text before the marker. The marker is not rendered.
3. Otherwise the body is trimmed to 600 Unicode code points on a
   whitespace boundary, without splitting a UTF-8 sequence.

## The kit

`gdefcore_render_kit` builds a tar archive with one member, named
`changeset`. It does not modify the catalog. `gdefcore_render_install`
reads that archive, applies the changeset, and stores the base theme,
the recent-posts view, and the two displays. It grants anonymous read
of `site.post`. The confirmation text is `anonymous means everyone
without an account`.

A second install writes nothing once the front and post displays exist.
If `site.post` exists and those displays do not, install does not apply
the changeset again. It still writes whichever of the theme, the view,
the displays, and the anonymous grant are missing. Render never opens
the archive: after install, the store is the only source.

The changeset defines the types. The theme, the view and the displays
are written after it applies, because an entity of a type cannot be
saved in the same changeset that defines the type.
