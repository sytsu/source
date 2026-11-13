# sytsu's apps

An AltStore / SideStore source with every app released on [github.com/sytsu](https://github.com/sytsu).

```
https://raw.githubusercontent.com/sytsu/source/main/apps.json
```

In AltStore or SideStore: **Sources › +**, paste the address above.

## How it stays up to date

Every hour, [`build_source.py`](build_source.py) looks at the releases of every public repository on the
account. Any release asset ending in `.ipa` is read for its name, bundle identifier, version, minimum
iOS version, entitlements, privacy strings and icon, and added to `apps.json`. Nothing has to be
listed by hand: a new repository with an IPA in a release shows up on the next run, and so does a new
release of an existing app. Up to ten versions per app are listed, newest first. A release whose IPA is
deleted drops out.

Run it now from **Actions › Update source › Run workflow**.

## Changing how an app is shown

[`config.json`](config.json) holds optional overrides per repository: `name`, `subtitle`,
`description`, `tintColor`, `category`, `screenshots`, or `"skip": true` to leave a repository out.
Without an entry, the name comes from the app and the description from the repository.
