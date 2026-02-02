# Change Log

## [5.1.3] - 2026-02-02

### Added

- Fine-Grained permissions for users based on claim - <https://github.com/Digitalist-Open-Cloud/Matomo-Plugin-RebelOIDC/pull/32>. Thanks to @daniellienert for this contribution.

## [5.1.2] - 2026-02-01

### Changed

- If token is encrypted, it should now succeed. Thanks to @ fpellet for this contribution.

## [5.1.1] - 2025-01-18

### Added

- Possibility to configure which claim to use for user name in Matomo - like id, email, preferred_username etc.

## [5.1.0] - 2025-01-17

### Added

- This plugin was released, with several fixes from the pull request queue from the original plugin [LoginOIDC](https://github.com/dominik-th/matomo-plugin-LoginOIDC). Changes will from now be documented in the Change Log. Also some new functions were added, that were not in the LoginOIDC pull request queue. Also, this plugin is not a drop in replacement for LoginOIDC, you need to remove LoginOIDC and add and install this plugin instead.
