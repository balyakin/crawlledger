# Protection Nginx fixture

This synthetic fixture validates `$uri` matching, exact and descendant path boundaries, longest-prefix
precedence, zero and non-zero burst behavior, static `403` signatures, and a deliberate location-level
`limit_req` shadow. A literal-dollar route verifies that generated regexes cannot be interpreted as Nginx
variables. The `/shadow/` location defines its own limiter, so Nginx does not inherit the emergency
server-level limiter there. Operators must inspect their locations for this native Nginx inheritance rule.
