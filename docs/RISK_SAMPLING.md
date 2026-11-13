# Risk Sampling

`config/risk.conf` defines nonnegative weights `alpha`, `beta`, and `gamma` that must sum to one, a positive `epsilon` no greater than one, and `decay_window` in rounds.

For each stripe, failure, repair, and anomaly counts are independently normalized as `min(count / decay_window, 1)`. The score is `q = alpha*f + beta*r + gamma*a`, so `q` remains in `[0,1]`. Each unselected shard receives weight `q + epsilon`, which keeps zero-risk stripes eligible. Risk sampling adds up to `cr` shards without removing baseline indices.

Supplemental selection uses an exponential race: each candidate receives `-ln(U)/(q+epsilon)` for a CSPRNG-derived `U` in `(0,1)`; the smallest keys are selected. This produces weighted sampling without replacement. The implementation currently accepts at most 1,000,000 shards per risk selection to bound memory and runtime.
