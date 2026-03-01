-- ==============================================================================
-- PAYMENT FRAUD HUNTING QUERIES
-- ==============================================================================
-- Author: Evgeniy Gantman
-- Purpose: Detect payment fraud patterns in transaction data
-- Use Case: Card testing, account takeover, velocity abuse
-- Data Source: Payment transaction database (PostgreSQL/Aurora)
-- ==============================================================================

-- ==============================================================================
-- QUERY 1: Card Testing Attack Detection
-- ==============================================================================
-- Attackers test stolen cards with small transactions to validate them

WITH card_testing_patterns AS (
  SELECT
    customer_ip,
    customer_email,
    DATE_TRUNC('hour', transaction_time) AS transaction_hour,
    COUNT(DISTINCT SUBSTRING(card_number, 1, 6)) AS unique_card_bins,  -- BIN = first 6 digits
    COUNT(*) AS total_transactions,
    SUM(CASE WHEN amount < 1.00 THEN 1 ELSE 0 END) AS micro_transactions,
    SUM(CASE WHEN status = 'declined' THEN 1 ELSE 0 END) AS declined_count,
    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved_count,
    ROUND(AVG(amount)::numeric, 2) AS avg_amount,
    COUNT(DISTINCT customer_email) AS unique_emails,
    COUNT(DISTINCT billing_zip) AS unique_zip_codes,
    ARRAY_AGG(DISTINCT card_brand) AS card_brands_used
  FROM
    payment_transactions
  WHERE
    transaction_time >= NOW() - INTERVAL '24 hours'
    AND transaction_time < NOW()
  GROUP BY
    customer_ip,
    customer_email,
    DATE_TRUNC('hour', transaction_time)
)
SELECT
  transaction_hour,
  customer_ip,
  customer_email,
  unique_card_bins,
  total_transactions,
  micro_transactions,
  declined_count,
  approved_count,
  ROUND((declined_count::numeric / NULLIF(total_transactions, 0) * 100), 2) AS decline_rate_pct,
  ROUND((micro_transactions::numeric / NULLIF(total_transactions, 0) * 100), 2) AS micro_txn_pct,
  avg_amount,
  unique_emails,
  unique_zip_codes,
  card_brands_used,
  CASE
    WHEN unique_card_bins >= 20 AND decline_rate_pct > 50
      THEN 'CRITICAL: Large-scale card testing with high decline rate'
    WHEN unique_card_bins >= 10 AND micro_txn_pct > 80
      THEN 'CRITICAL: Card testing with micro-transactions'
    WHEN unique_card_bins >= 10 AND decline_rate_pct > 30
      THEN 'HIGH: Multiple cards tested with suspicious decline rate'
    WHEN unique_card_bins >= 5 AND total_transactions > 50
      THEN 'MEDIUM: Moderate card testing activity'
    ELSE 'LOW: Possible legitimate activity'
  END AS risk_level
FROM
  card_testing_patterns
WHERE
  -- Alert criteria
  (unique_card_bins >= 10  -- Testing 10+ different cards
   OR (declined_count::numeric / NULLIF(total_transactions, 0)) > 0.30  -- >30% decline rate
   OR (micro_transactions::numeric / NULLIF(total_transactions, 0)) > 0.50)  -- >50% micro transactions
ORDER BY
  unique_card_bins DESC,
  declined_count DESC
LIMIT 100;


-- ==============================================================================
-- QUERY 2: Velocity Abuse Detection (Rapid Transaction Attempts)
-- ==============================================================================

WITH transaction_velocity AS (
  SELECT
    customer_id,
    customer_email,
    customer_ip,
    card_number_hash,  -- Assuming PCI-compliant hashed card number
    COUNT(*) AS transaction_count,
    MIN(transaction_time) AS first_transaction,
    MAX(transaction_time) AS last_transaction,
    EXTRACT(EPOCH FROM (MAX(transaction_time) - MIN(transaction_time))) / 60 AS time_window_minutes,
    SUM(amount) AS total_amount,
    ROUND(AVG(amount)::numeric, 2) AS avg_amount,
    COUNT(DISTINCT merchant_id) AS unique_merchants,
    COUNT(DISTINCT billing_country) AS unique_countries
  FROM
    payment_transactions
  WHERE
    transaction_time >= NOW() - INTERVAL '1 hour'
  GROUP BY
    customer_id,
    customer_email,
    customer_ip,
    card_number_hash
)
SELECT
  customer_id,
  customer_email,
  customer_ip,
  transaction_count,
  ROUND(time_window_minutes::numeric, 2) AS time_window_minutes,
  ROUND((transaction_count::numeric / NULLIF(time_window_minutes, 0)), 2) AS transactions_per_minute,
  total_amount,
  avg_amount,
  unique_merchants,
  unique_countries,
  first_transaction,
  last_transaction,
  CASE
    WHEN transaction_count >= 100 AND time_window_minutes < 5
      THEN 'CRITICAL: Extreme velocity (100+ txns in <5 min)'
    WHEN transaction_count >= 50 AND time_window_minutes < 10
      THEN 'HIGH: High velocity (50+ txns in <10 min)'
    WHEN transaction_count >= 20 AND time_window_minutes < 5
      THEN 'HIGH: Rapid transaction burst'
    WHEN unique_countries > 3
      THEN 'HIGH: Multiple countries in short timeframe'
    WHEN transaction_count >= 10 AND time_window_minutes < 10
      THEN 'MEDIUM: Elevated transaction rate'
    ELSE 'LOW: Normal velocity'
  END AS risk_level
FROM
  transaction_velocity
WHERE
  transaction_count >= 10  -- 10+ transactions
  OR time_window_minutes < 5  -- Within 5 minutes
  OR unique_countries > 2  -- Transactions from >2 countries
ORDER BY
  transaction_count DESC,
  time_window_minutes ASC
LIMIT 100;


-- ==============================================================================
-- QUERY 3: Account Takeover Detection (Changed Payment Methods)
-- ==============================================================================

WITH recent_payment_changes AS (
  SELECT
    customer_id,
    customer_email,
    card_number_hash,
    transaction_time,
    LAG(card_number_hash) OVER (PARTITION BY customer_id ORDER BY transaction_time) AS previous_card,
    LAG(billing_zip) OVER (PARTITION BY customer_id ORDER BY transaction_time) AS previous_zip,
    billing_zip,
    LAG(customer_ip) OVER (PARTITION BY customer_id ORDER BY transaction_time) AS previous_ip,
    customer_ip,
    amount,
    status
  FROM
    payment_transactions
  WHERE
    transaction_time >= NOW() - INTERVAL '7 days'
),
suspicious_changes AS (
  SELECT
    customer_id,
    customer_email,
    transaction_time,
    card_number_hash AS new_card,
    previous_card,
    customer_ip AS new_ip,
    previous_ip,
    billing_zip AS new_zip,
    previous_zip,
    amount,
    status,
    CASE
      WHEN previous_card IS NOT NULL AND card_number_hash != previous_card THEN 1 ELSE 0
    END AS card_changed,
    CASE
      WHEN previous_ip IS NOT NULL AND customer_ip != previous_ip THEN 1 ELSE 0
    END AS ip_changed,
    CASE
      WHEN previous_zip IS NOT NULL AND billing_zip != previous_zip THEN 1 ELSE 0
    END AS zip_changed
  FROM
    recent_payment_changes
  WHERE
    previous_card IS NOT NULL
)
SELECT
  customer_id,
  customer_email,
  transaction_time,
  new_ip,
  previous_ip,
  new_card,
  new_zip,
  previous_zip,
  amount,
  status,
  (card_changed + ip_changed + zip_changed) AS total_changes,
  CASE
    WHEN card_changed = 1 AND ip_changed = 1 AND zip_changed = 1 AND amount > 500
      THEN 'CRITICAL: All details changed + high-value transaction'
    WHEN card_changed = 1 AND ip_changed = 1 AND amount > 100
      THEN 'HIGH: Card and IP changed with significant purchase'
    WHEN card_changed = 1 AND ip_changed = 1
      THEN 'MEDIUM: Card and IP changed simultaneously'
    WHEN card_changed = 1 AND amount > 500
      THEN 'MEDIUM: New card used for high-value purchase'
    ELSE 'LOW: Single attribute change'
  END AS risk_level
FROM
  suspicious_changes
WHERE
  card_changed = 1 OR ip_changed = 1 OR zip_changed = 1
ORDER BY
  total_changes DESC,
  amount DESC
LIMIT 100;


-- ==============================================================================
-- QUERY 4: Geolocation Anomaly Detection (Impossible Travel)
-- ==============================================================================

WITH transaction_locations AS (
  SELECT
    customer_id,
    customer_email,
    transaction_time,
    customer_ip,
    billing_country,
    billing_city,
    amount,
    status,
    LAG(transaction_time) OVER (PARTITION BY customer_id ORDER BY transaction_time) AS prev_transaction_time,
    LAG(billing_country) OVER (PARTITION BY customer_id ORDER BY transaction_time) AS prev_country,
    LAG(billing_city) OVER (PARTITION BY customer_id ORDER BY transaction_time) AS prev_city
  FROM
    payment_transactions
  WHERE
    transaction_time >= NOW() - INTERVAL '7 days'
),
travel_analysis AS (
  SELECT
    customer_id,
    customer_email,
    transaction_time,
    prev_transaction_time,
    EXTRACT(EPOCH FROM (transaction_time - prev_transaction_time)) / 3600 AS hours_between,
    billing_country,
    prev_country,
    billing_city,
    prev_city,
    customer_ip,
    amount,
    status
  FROM
    transaction_locations
  WHERE
    prev_transaction_time IS NOT NULL
    AND billing_country != prev_country  -- Different countries
    AND prev_country IS NOT NULL
)
SELECT
  customer_id,
  customer_email,
  prev_country || ' -> ' || billing_country AS country_change,
  prev_city || ' -> ' || billing_city AS city_change,
  ROUND(hours_between::numeric, 2) AS hours_between_transactions,
  prev_transaction_time,
  transaction_time,
  customer_ip,
  amount,
  status,
  CASE
    WHEN hours_between < 1 THEN 'CRITICAL: Country change in <1 hour (impossible travel)'
    WHEN hours_between < 4 THEN 'HIGH: Country change in <4 hours (highly suspicious)'
    WHEN hours_between < 24 THEN 'MEDIUM: Country change in <24 hours (possible travel)'
    ELSE 'LOW: Country change with reasonable time gap'
  END AS risk_level
FROM
  travel_analysis
WHERE
  hours_between < 24  -- Focus on rapid country changes
ORDER BY
  hours_between ASC,
  amount DESC
LIMIT 100;


-- ==============================================================================
-- QUERY 5: Suspicious High-Value Transactions
-- ==============================================================================

WITH customer_baselines AS (
  SELECT
    customer_id,
    AVG(amount) AS avg_transaction_amount,
    STDDEV(amount) AS stddev_amount,
    MAX(amount) AS historical_max_amount,
    COUNT(*) AS total_transactions
  FROM
    payment_transactions
  WHERE
    transaction_time >= NOW() - INTERVAL '90 days'
    AND transaction_time < NOW() - INTERVAL '24 hours'  -- Exclude last 24 hours
    AND status = 'approved'
  GROUP BY
    customer_id
  HAVING
    COUNT(*) >= 5  -- At least 5 historical transactions for baseline
),
recent_transactions AS (
  SELECT
    t.customer_id,
    t.customer_email,
    t.transaction_time,
    t.amount,
    t.customer_ip,
    t.billing_country,
    t.merchant_id,
    t.status,
    b.avg_transaction_amount,
    b.stddev_amount,
    b.historical_max_amount
  FROM
    payment_transactions t
  JOIN
    customer_baselines b ON t.customer_id = b.customer_id
  WHERE
    t.transaction_time >= NOW() - INTERVAL '24 hours'
)
SELECT
  customer_id,
  customer_email,
  transaction_time,
  amount,
  ROUND(avg_transaction_amount::numeric, 2) AS baseline_avg,
  ROUND((amount - avg_transaction_amount) / NULLIF(stddev_amount, 0), 2) AS z_score,
  ROUND((amount / NULLIF(avg_transaction_amount, 0))::numeric, 2) AS amount_multiplier,
  historical_max_amount,
  customer_ip,
  billing_country,
  merchant_id,
  status,
  CASE
    WHEN amount > avg_transaction_amount * 10 AND amount > 1000
      THEN 'CRITICAL: 10x normal amount + high value ($1000+)'
    WHEN amount > historical_max_amount * 2 AND amount > 500
      THEN 'HIGH: 2x historical maximum'
    WHEN (amount - avg_transaction_amount) / NULLIF(stddev_amount, 0) > 5
      THEN 'HIGH: >5 standard deviations from average'
    WHEN amount > avg_transaction_amount * 5
      THEN 'MEDIUM: 5x normal transaction amount'
    ELSE 'LOW: Within expected range'
  END AS risk_level
FROM
  recent_transactions
WHERE
  amount > avg_transaction_amount * 3  -- At least 3x normal
  OR amount > historical_max_amount
ORDER BY
  z_score DESC NULLS LAST,
  amount DESC
LIMIT 100;


-- ==============================================================================
-- QUERY 6: Compromised Card Detection (Multiple Failed Then Success)
-- ==============================================================================

WITH failed_transactions AS (
  SELECT
    card_number_hash,
    customer_ip,
    COUNT(*) AS failed_count,
    MIN(transaction_time) AS first_failed,
    MAX(transaction_time) AS last_failed,
    ARRAY_AGG(DISTINCT decline_reason) AS decline_reasons
  FROM
    payment_transactions
  WHERE
    transaction_time >= NOW() - INTERVAL '1 hour'
    AND status = 'declined'
  GROUP BY
    card_number_hash,
    customer_ip
  HAVING
    COUNT(*) >= 3  -- 3+ failed attempts
),
successful_after_failures AS (
  SELECT
    s.transaction_time AS success_time,
    s.customer_id,
    s.customer_email,
    s.card_number_hash,
    s.customer_ip,
    s.amount,
    s.billing_country,
    f.failed_count,
    f.first_failed,
    f.last_failed,
    f.decline_reasons,
    EXTRACT(EPOCH FROM (s.transaction_time - f.last_failed)) / 60 AS minutes_after_failures
  FROM
    payment_transactions s
  JOIN
    failed_transactions f
    ON s.card_number_hash = f.card_number_hash
    AND s.customer_ip = f.customer_ip
  WHERE
    s.transaction_time >= NOW() - INTERVAL '1 hour'
    AND s.status = 'approved'
    AND s.transaction_time > f.last_failed
)
SELECT
  success_time,
  customer_id,
  customer_email,
  customer_ip,
  billing_country,
  failed_count,
  ROUND(minutes_after_failures::numeric, 2) AS minutes_after_last_failure,
  first_failed,
  last_failed,
  decline_reasons,
  amount,
  CASE
    WHEN failed_count >= 10 AND minutes_after_failures < 5
      THEN 'CRITICAL: Success after 10+ failures within 5 minutes'
    WHEN failed_count >= 5 AND amount > 500
      THEN 'HIGH: Success after multiple failures + high value'
    WHEN failed_count >= 5
      THEN 'MEDIUM: Success after multiple failed attempts'
    ELSE 'LOW: Few failures before success'
  END AS risk_level
FROM
  successful_after_failures
ORDER BY
  failed_count DESC,
  amount DESC
LIMIT 100;

-- ==============================================================================
-- INVESTIGATION PLAYBOOK
-- ==============================================================================
-- For each alert:
-- 1. [ ] Block suspicious IP at WAF level
-- 2. [ ] Notify fraud team via PagerDuty/email
-- 3. [ ] Contact customer if account takeover suspected
-- 4. [ ] Review full transaction history for customer/IP
-- 5. [ ] Check if card(s) flagged in fraud database
-- 6. [ ] Correlate with Wazuh SIEM alerts for same IP
-- 7. [ ] Create incident ticket and document findings
-- 8. [ ] Consider temporary freeze on customer account
-- ==============================================================================
