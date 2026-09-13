# Driver boundary

Digital Archaeologist v1 contains **no kernel drivers**. The driver directories are reserved for future, separately reviewed, read-only adapters.

Any future experimental adapter must be opt-in, never silently installed, never auto-loaded, and validated against a user-space parser first. Disk writes must remain disabled by default.
