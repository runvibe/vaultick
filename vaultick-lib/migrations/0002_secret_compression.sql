PRAGMA foreign_keys = OFF;

ALTER TABLE secrets
    ADD COLUMN compression TEXT NOT NULL DEFAULT 'none'
    CHECK (compression IN ('none', 'zstd'));

ALTER TABLE secrets
    ADD COLUMN original_size INTEGER;

PRAGMA user_version = 2;
PRAGMA foreign_keys = ON;
