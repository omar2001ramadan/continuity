ALTER TABLE trust_assessments_v2
  ADD COLUMN IF NOT EXISTS feature_vector_commitment TEXT
  CHECK (feature_vector_commitment IS NULL OR feature_vector_commitment ~ '^0x[0-9a-f]{64}$');
