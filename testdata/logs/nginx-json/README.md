# Nginx JSON fixtures

`valid.jsonl` has two accepted records with request, upstream and cache metrics. It also carries the
`nginx_uri` and `limit_req_status` fields required by the optional protection watcher; offline analysis
deliberately tolerates them. `invalid.jsonl` contains a known-field type error and a negative duration.
