# Kauri
Kauri takes heavy inspiration from the Cowrie SSH honeypot.

The goal of this project is to eventually become feature-compatible with Ubuntu's latest LTS release while providing a limited attack-surface (especially against fingerprinting). At the moment of writing, this target is Ubuntu 20.04 LTS.

Not only does this result in an easier-to-maintain codebase, but it allows more specific work to be done on a convincing SSH server. Once an APT cannot reasonably distinguish between Kauri and a legitimate Ubuntu LTS server, our job is done. 🍺
