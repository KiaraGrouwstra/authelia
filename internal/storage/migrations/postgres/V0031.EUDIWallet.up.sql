CREATE TABLE IF NOT EXISTS eudi_wallet_transaction (
    id VARCHAR(255) NOT NULL,
    key_id VARCHAR(255) NOT NULL DEFAULT '',
    response_code_hash VARCHAR(255) NOT NULL DEFAULT '',
    version BIGINT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    data BYTEA NOT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX eudi_wallet_transaction_key_id_idx ON eudi_wallet_transaction (key_id);
CREATE INDEX eudi_wallet_transaction_response_code_hash_idx ON eudi_wallet_transaction (response_code_hash);
CREATE INDEX eudi_wallet_transaction_expires_at_idx ON eudi_wallet_transaction (expires_at);
