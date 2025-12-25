-- Migration: Update sessions table for session-based authentication
-- Run this SQL in your Supabase SQL Editor

-- Step 1: Add session_id column (unique, not null after we populate it)
ALTER TABLE sessions 
ADD COLUMN IF NOT EXISTS session_id VARCHAR(64);

-- Step 2: Make user_id nullable (it was required before, now it can be null for anonymous sessions)
ALTER TABLE sessions 
ALTER COLUMN user_id DROP NOT NULL;

-- Step 3: Add new tracking columns
ALTER TABLE sessions 
ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45),
ADD COLUMN IF NOT EXISTS user_agent VARCHAR(500),
ADD COLUMN IF NOT EXISTS last_accessed_at TIMESTAMPTZ DEFAULT NOW();

-- Step 4: Make title nullable (it was required before, now optional for anonymous sessions)
ALTER TABLE sessions 
ALTER COLUMN title DROP NOT NULL;

-- Step 5: Create unique index on session_id (after adding the column)
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id);

-- Step 6: Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

-- Step 7: Update foreign key constraint to allow null (if it doesn't already)
-- Note: This might fail if there's a constraint, but that's okay - the column is already nullable
DO $$
BEGIN
    -- Try to drop and recreate the foreign key to allow nulls
    ALTER TABLE sessions 
    DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;
    
    ALTER TABLE sessions 
    ADD CONSTRAINT sessions_user_id_fkey 
    FOREIGN KEY (user_id) 
    REFERENCES users(id) 
    ON DELETE SET NULL;
EXCEPTION
    WHEN others THEN
        -- Constraint might not exist or already be correct, ignore
        NULL;
END $$;

-- Verification: Check the table structure
-- SELECT column_name, data_type, is_nullable 
-- FROM information_schema.columns 
-- WHERE table_name = 'sessions' 
-- ORDER BY ordinal_position;

