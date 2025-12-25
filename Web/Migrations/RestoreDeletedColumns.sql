-- Migration: Restore deleted columns in users and sessions tables
-- Run this SQL in your Supabase SQL Editor

-- ============================================
-- RESTORE COLUMNS IN users TABLE
-- ============================================

-- Add auth_provider column back to users table
ALTER TABLE public.users 
ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(50) NOT NULL DEFAULT 'local';

-- ============================================
-- RESTORE COLUMNS IN sessions TABLE
-- ============================================

-- Add session_id column (unique identifier for cookie-based sessions)
ALTER TABLE public.sessions 
ADD COLUMN IF NOT EXISTS session_id VARCHAR(64);

-- Add ip_address column (for tracking user IP)
ALTER TABLE public.sessions 
ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);

-- Add user_agent column (for tracking browser information)
ALTER TABLE public.sessions 
ADD COLUMN IF NOT EXISTS user_agent VARCHAR(500);

-- Add last_accessed_at column (for tracking last access time)
ALTER TABLE public.sessions 
ADD COLUMN IF NOT EXISTS last_accessed_at TIMESTAMPTZ DEFAULT NOW();

-- Make user_id nullable (for anonymous sessions)
ALTER TABLE public.sessions 
ALTER COLUMN user_id DROP NOT NULL;

-- Create unique index on session_id
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_session_id ON public.sessions(session_id);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON public.sessions(user_id);

-- Update foreign key constraint to allow null user_id
DO $$
BEGIN
    ALTER TABLE public.sessions 
    DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;
    
    ALTER TABLE public.sessions 
    ADD CONSTRAINT sessions_user_id_fkey 
    FOREIGN KEY (user_id) 
    REFERENCES public.users(id) 
    ON DELETE SET NULL;
EXCEPTION
    WHEN others THEN
        NULL;
END $$;

-- Verification queries (optional - run to check):
-- SELECT column_name, data_type, is_nullable 
-- FROM information_schema.columns 
-- WHERE table_schema = 'public' AND table_name = 'users' 
-- ORDER BY ordinal_position;
--
-- SELECT column_name, data_type, is_nullable 
-- FROM information_schema.columns 
-- WHERE table_schema = 'public' AND table_name = 'sessions' 
-- ORDER BY ordinal_position;

